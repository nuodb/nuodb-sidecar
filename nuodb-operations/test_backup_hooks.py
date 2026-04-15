#!/usr/bin/env python

import logging
import os
import shutil
import unittest
from unittest import mock
import socket
import time
import importlib
import json
import uuid
import http
from http.client import HTTPConnection
from threading import Thread
from wsgiref.simple_server import make_server
import sys
import shlex

import metrics
import backup_hooks
from backup_hooks import HooksHandler, LOGGER

LOGGER.setLevel(logging.DEBUG)


def retry(check_fn, timeout, initial_delay=0.25, max_delay=5):
    delay = initial_delay
    start_time = time.time()
    while True:
        try:
            return check_fn()
        except Exception:
            remaining = timeout - (time.time() - start_time)
            if remaining > 0:
                time.sleep(max(initial_delay, min(remaining, delay)))
                delay = min(max_delay, 2 * delay)
            else:
                raise


class ConfigOverrides(object):
    def __init__(self, **overrides):
        self.overrides = overrides

    def __call__(self, testMethod):
        testMethod.overrides = self.overrides
        return testMethod


class HttpHandlersTests(unittest.TestCase):
    hooks_dir = os.path.dirname(os.path.abspath(__file__))
    test_results_dir = os.path.join(
        os.path.dirname(hooks_dir), "test-results", "nuodb-operations"
    )

    @classmethod
    def setUpClass(cls):
        # create test results directories
        os.makedirs(cls.test_results_dir, exist_ok=True)
        cls.tmp_dir = os.path.join(cls.test_results_dir, "tmp", cls.__name__)
        # clean and re-create tmp diretory
        shutil.rmtree(cls.tmp_dir, ignore_errors=True)
        os.makedirs(cls.tmp_dir)
        # placeholder for server configuration
        cls.server_config = {}

    @staticmethod
    def get_local_port():
        sock = socket.socket()
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()
        sock.close()
        return port[1]

    def get_server_config(self):
        config = getattr(self, "server_config", {})
        testMethod = getattr(self, self._testMethodName)
        overrides = getattr(testMethod, "overrides", {})
        config.update(overrides)
        return config

    def configure_server(self):
        server_config = self.get_server_config()
        # Configure environment variables
        if server_config.get("has_archives", True):
            self.archive_dir = os.path.join(self.test_dir, "archive")
            os.makedirs(self.archive_dir)
            os.environ["NUODB_ARCHIVE_DIR"] = self.archive_dir
        if server_config.get("external_journal", False):
            self.journal_dir = os.path.join(self.test_dir, "journal")
            os.makedirs(self.journal_dir)
            os.environ["NUODB_JOURNAL_DIR"] = self.journal_dir
        # Configure custom handlers
        handler_config = None
        custom_handlers = server_config.get("custom_handlers")
        if custom_handlers:
            handler_config = os.path.join(self.test_dir, "handlers.json")
            with open(handler_config, "w") as f:
                f.write(json.dumps(dict(handlers=custom_handlers)))
        # Reload ensures that env changes are picked up and metrics are reset
        importlib.reload(metrics)
        importlib.reload(backup_hooks)
        # Mock functions
        self.mock_functions()
        return handler_config

    def setUp(self):
        # Create test tmp directory
        self.test_dir = os.path.join(self.tmp_dir, self._testMethodName)
        os.makedirs(self.test_dir)
        # Configure the server
        self.original_env = os.environ
        self.start_server()
        self._wait_until_ready()

    def mock_functions(self):
        pass

    def tearDown(self):
        self.stop_server()
        # Restore environment variables
        os.environ.clear()
        os.environ.update(self.original_env)

    def _wait_until_ready(self, timeout=5):
        def _connect():
            conn = HTTPConnection(self.host, self.port)
            conn.connect()
            conn.close()

        retry(lambda: _connect(), timeout)

    def _wait_until_stopped(self, timeout=5):
        def _connect():
            conn = HTTPConnection(self.host, self.port)
            try:
                conn.connect()
                raise RuntimeError("Server is running")
            except Exception:
                return
            finally:
                conn.close()

        retry(lambda: _connect(), timeout)

    def start_server(self, handler_config=None):
        handler_config = self.configure_server()
        self.host = "127.0.0.1"
        self.port = self.get_local_port()
        LOGGER.info("Starting hooks server on %s:%d", self.host, self.port)
        self.httpd = make_server(self.host, self.port, HooksHandler(handler_config))
        self.server_thread = Thread(target=self.httpd.serve_forever, daemon=True)
        self.server_thread.start()
        self._wait_until_ready()

    def stop_server(self):
        if self.httpd:
            self.httpd.shutdown()
            self.httpd.server_close()
            self.server_thread.join()
            self._wait_until_stopped()
            LOGGER.info("Server stopped")

    def request(self, path="/", method="GET", body=None, headers=None):
        headers = headers or {}
        conn = HTTPConnection(self.host, self.port)
        try:
            conn.request(method, path, body=body, headers=headers)
            resp = conn.getresponse()
            data = resp.read()
            return resp, data
        finally:
            conn.close()

    @ConfigOverrides(
        custom_handlers=[
            {
                "method": "GET",
                "path": "/exit",
                "script": "exit ${code:=0}",
                "statusMappings": {"1": 500, "2": 400},
            }
        ]
    )
    def testMetrics(self):
        # request metrics endpoint
        resp, data = self.request(method="GET", path="/metrics")
        self.assertEqual(http.HTTPStatus.OK, resp.status, str(data))
        out = data.decode("utf-8")

        # request metrics endpoint again
        resp, data = self.request(method="GET", path="/metrics")
        self.assertEqual(http.HTTPStatus.OK, resp.status, str(data))
        out = data.decode("utf-8")

        # verify that hook request latency Histogram is emitted
        self.assertIn(
            'hook_request_duration_seconds_bucket{le="1.0",method="GET",endpoint="/metrics",http_status="200"} 1',
            out,
        )
        self.assertIn(
            'hook_request_duration_seconds_bucket{le="+Inf",method="GET",endpoint="/metrics",http_status="200"} 1',
            out,
        )
        self.assertIn(
            'hook_request_duration_seconds_bucket{le="+Inf",method="GET",endpoint="/metrics",http_status="200"} 1',
            out,
        )
        self.assertIn(
            'hook_request_duration_seconds_count{method="GET",endpoint="/metrics",http_status="200"} 1',
            out,
        )
        self.assertIn(
            'hook_request_duration_seconds_sum{method="GET",endpoint="/metrics",http_status="200"}',
            out,
        )

        # request custom handler
        resp, data = self.request(method="GET", path="/exit")
        self.assertEqual(http.HTTPStatus.OK, resp.status, str(data))
        resp, data = self.request(method="GET", path="/exit?code=1")
        self.assertEqual(http.HTTPStatus.INTERNAL_SERVER_ERROR, resp.status, str(data))
        resp, data = self.request(method="GET", path="/exit?code=2")
        self.assertEqual(http.HTTPStatus.BAD_REQUEST, resp.status, str(data))

        # request metrics endpoint again
        resp, data = self.request(method="GET", path="/metrics")
        self.assertEqual(http.HTTPStatus.OK, resp.status, str(data))
        out = data.decode("utf-8")

        # verify that hook request latency Histogram is emitted
        self.assertIn(
            'hook_request_duration_seconds_bucket{le="+Inf",method="GET",endpoint="/exit",http_status="200"} 1',
            out,
        )
        self.assertIn(
            'hook_request_duration_seconds_count{method="GET",endpoint="/exit",http_status="200"} 1',
            out,
        )
        self.assertIn(
            'hook_request_duration_seconds_sum{method="GET",endpoint="/exit",http_status="200"}',
            out,
        )
        self.assertIn(
            'hook_request_duration_seconds_bucket{le="+Inf",method="GET",endpoint="/exit",http_status="500"} 1',
            out,
        )
        self.assertIn(
            'hook_request_duration_seconds_count{method="GET",endpoint="/exit",http_status="500"} 1',
            out,
        )
        self.assertIn(
            'hook_request_duration_seconds_sum{method="GET",endpoint="/exit",http_status="500"}',
            out,
        )
        self.assertIn(
            'hook_request_duration_seconds_bucket{le="+Inf",method="GET",endpoint="/exit",http_status="400"} 1',
            out,
        )
        self.assertIn(
            'hook_request_duration_seconds_count{method="GET",endpoint="/exit",http_status="400"} 1',
            out,
        )
        self.assertIn(
            'hook_request_duration_seconds_sum{method="GET",endpoint="/exit",http_status="400"}',
            out,
        )


class BackupHooksTest(HttpHandlersTests):

    def path(self, *args):
        return os.path.join(self.test_dir, *args)

    def mock_functions(self):
        server_config = self.get_server_config()
        nuodb_processes = server_config.get(
            "nuodb_processes", [{"pid": 1234, "sid": 0}]
        )
        self.nuodb_processes_patch = mock.patch(
            "backup_hooks.get_nuodb_process_info", return_value=nuodb_processes
        )
        self.nuodb_processes_mock = self.nuodb_processes_patch.start()

    def tearDown(self):
        self.nuodb_processes_patch.stop()
        super().tearDown()

    def pre_backup(self, backup_id, opaque=None):
        resp, data = self.request(
            method="POST",
            path=f"/pre-backup/{backup_id}",
            body=json.dumps(dict(opaque=opaque)),
            headers={"Content-Type": "application/json"},
        )
        return resp, json.loads(data)

    def post_backup(self, backup_id, force=False):
        resp, data = self.request(
            method="POST",
            path=f"/post-backup/{backup_id}?force={str(force).lower()}",
        )
        return resp, json.loads(data)

    def assertFileContent(self, name, content):
        file = self.path(name)
        self.assertTrue(os.path.isfile(file), f"File {file} does not exist")
        with open(file, "r") as f:
            actual = f.read()
            self.assertEqual(content, actual, f"File {file} content differ")

    def assertFileNotExist(self, name):
        file = self.path(name)
        self.assertFalse(os.path.exists(file), f"File {file} still exists")

    @mock.patch("backup_hooks.freeze_archive")
    def testPrePostHooks(self, freeze_archive_mock=None):
        external_journal = self.get_server_config().get("external_journal", False)
        backup_id = str(uuid.uuid4())

        # Invoke pre-backup hook
        user_data = "user data to store"
        resp, data = self.pre_backup(backup_id, opaque=user_data)
        self.assertEqual(http.HTTPStatus.OK, resp.status, str(data))
        self.assertTrue(data["success"], "pre-backup hook reported failure")

        # verify that backup.txt and backup_payload.txt files are created
        self.assertFileContent(os.path.join(self.archive_dir, "backup.txt"), backup_id)
        self.assertFileContent(
            os.path.join(self.archive_dir, "backup_payload.txt"), user_data
        )
        # check if the archive is frozen; the archive should be frozen only if
        # external journal is enabled
        if not external_journal:
            freeze_archive_mock.assert_not_called()
        else:
            freeze_archive_mock.assert_called_once_with(
                backup_id, self.nuodb_processes_mock.return_value, timeout=None
            )

        # negative test: invoke post-backup with bogus backup_id
        resp, data = self.post_backup("bogus")
        self.assertEqual(http.HTTPStatus.BAD_REQUEST, resp.status, str(data))
        self.assertFalse(data["success"], "post-backup hook reported success")
        self.assertIn(
            f"Unexpected backup ID: current={backup_id}, supplied=bogus",
            data.get("message"),
        )

        # Invoke post-backup hook
        resp, data = self.post_backup(backup_id)
        self.assertEqual(http.HTTPStatus.OK, resp.status, str(data))
        self.assertTrue(data["success"], "post-backup hook reported failure")

        # verify that backup.txt and backup_payload.txt files are removed
        self.assertFileNotExist(os.path.join(self.archive_dir, "backup.txt"))
        self.assertFileNotExist(os.path.join(self.archive_dir, "backup_payload.txt"))

        # check if the archive is unfrozen; the archive should be unfrozen only
        # if external journal is enabled
        if not external_journal:
            freeze_archive_mock.assert_not_called()
        else:
            freeze_archive_mock.assert_called_with(
                backup_id, self.nuodb_processes_mock.return_value, unfreeze=True
            )

        # negative test: invoking post-backup again should fail
        resp, data = self.post_backup(backup_id)
        self.assertEqual(http.HTTPStatus.BAD_REQUEST, resp.status, str(data))
        self.assertFalse(data["success"], "post-backup hook reported success")
        self.assertIn(
            f"Unexpected backup ID: current=None, supplied={backup_id}",
            data.get("message"),
        )

    @ConfigOverrides(
        custom_handlers=[
            {
                "method": "GET",
                "path": "/exit",
                "script": "exit ${code:=0}",
                "statusMappings": {"1": 500, "2": 400},
            }
        ]
    )
    def testBackupHookMetrics(self):
        # request metrics endpoint
        resp, data = self.request(method="GET", path="/metrics")
        self.assertEqual(http.HTTPStatus.OK, resp.status, str(data))
        out = data.decode("utf-8")

        # verify that volume metrics are reported
        self.assertRegex(
            out, 'nuodb_volume_available_bytes{volume="archive-volume"} [0-9]+'
        )
        if self.get_server_config().get("external_journal", False):
            self.assertRegex(
                out, 'nuodb_volume_available_bytes{volume="journal-volume"} [0-9]+'
            )
        else:
            self.assertNotIn(
                'nuodb_volume_available_bytes{volume="journal-volume"}', out
            )

        # call backup hooks
        backup_id = str(uuid.uuid4())
        resp, data = self.pre_backup(backup_id)
        self.assertEqual(http.HTTPStatus.OK, resp.status, str(data))
        time.sleep(0.6)
        resp, data = self.post_backup(backup_id)
        self.assertEqual(http.HTTPStatus.OK, resp.status, str(data))

        # request metrics endpoint again
        resp, data = self.request(method="GET", path="/metrics")
        self.assertEqual(http.HTTPStatus.OK, resp.status, str(data))
        out = data.decode("utf-8")

        # verify that nuodb_archive_frozen_seconds Histogram is emitted
        self.assertIn('snapshot_backup_duration_seconds_bucket{le="0.5"} 0', out)
        self.assertIn('snapshot_backup_duration_seconds_bucket{le="1.0"} 1', out)
        self.assertIn('snapshot_backup_duration_seconds_bucket{le="+Inf"} 1', out)
        self.assertIn("snapshot_backup_duration_seconds_count 1", out)
        self.assertIn("snapshot_backup_duration_seconds_sum", out)
        self.assertNotIn("snapshot_backup_duration_seconds 0", out)


class BackupHooksExternalJournalTest(BackupHooksTest):

    def mock_functions(self):
        super().mock_functions()
        self.freeze_archive_patch = mock.patch("backup_hooks.freeze_archive")
        self.freeze_archive_mock = self.freeze_archive_patch.start()

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.server_config = dict(external_journal=True)

    def tearDown(self):
        super().tearDown()
        self.freeze_archive_patch.stop()


class NoArchivesHandlersTest(HttpHandlersTests):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.server_config = dict(has_archives=False)

    def testNoHooks(self):
        resp, data = self.request(
            method="POST",
            path=f"/pre-backup/{uuid.uuid4()}",
            body=None,
            headers={"Content-Type": "application/json"},
        )
        data = json.loads(data)
        self.assertEqual(http.HTTPStatus.BAD_REQUEST, resp.status, str(data))
        self.assertFalse(data["success"])
        self.assertIn("No handler found for path /pre-backup/", data["message"])

        resp, data = self.request(
            method="POST",
            path=f"/post-backup/{uuid.uuid4()}",
        )
        data = json.loads(data)
        self.assertEqual(http.HTTPStatus.BAD_REQUEST, resp.status, str(data))
        self.assertFalse(data["success"])
        self.assertIn("No handler found for path /post-backup/", data["message"])

    def testNoArchiveMetrics(self):
        # request metrics endpoint
        resp, data = self.request(method="GET", path="/metrics")
        self.assertEqual(http.HTTPStatus.OK, resp.status, str(data))
        out = data.decode("utf-8")

        # verify that volume metrics are reported
        self.assertNotIn('nuodb_volume_available_bytes{volume="archive-volume"}', out)

        self.assertNotIn('nuodb_volume_available_bytes{volume="journal-volume"}', out)


class CliTests(unittest.TestCase):
    def testNoArchives(self):
        "Test CLI options that should be disabled if no archive directory is configured"
        with mock.patch.dict("os.environ") as mockenv:
            mockenv.pop("NUODB_ARCHIVE_DIR", None)

            with mock.patch.object(
                sys,
                "argv",
                shlex.split("backup_hooks.py pre-hook --backup-id not-needed"),
            ):
                mockenv.pop("NUODB_ARCHIVE_DIR", None)
                self.assertRaisesRegex(
                    RuntimeError,
                    "No archive path configured on this container",
                    backup_hooks.main,
                )

            with mock.patch.object(
                sys,
                "argv",
                shlex.split("backup_hooks.py post-hook --backup-id not-needed"),
            ):
                mockenv.pop("NUODB_ARCHIVE_DIR", None)
                self.assertRaisesRegex(
                    RuntimeError,
                    "No archive path configured on this container",
                    backup_hooks.main,
                )


if __name__ == "__main__":
    unittest.main()
