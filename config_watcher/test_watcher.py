#!/usr/bin/env python

import logging
import os
import shutil
import subprocess
import sys
import unittest
import string
import random
import time
import http.server
from http import HTTPStatus
import threading
from subprocess import TimeoutExpired

from kubernetes import client, config
from kubernetes.config.kube_config import KUBE_CONFIG_DEFAULT_LOCATION

from watcher import RESOURCE_CONFIGMAP, RESOURCE_SECRET, LOGGER

LOGGER.setLevel(logging.DEBUG)


def rand_str(length, prefix=""):
    return "".join(
        [prefix] + random.choices(string.ascii_lowercase + string.digits, k=length)
    )


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


class WatcherTest(unittest.TestCase):
    watcher_dir = os.path.dirname(os.path.abspath(__file__))
    test_results_dir = os.path.join(
        os.path.dirname(watcher_dir), "test-results", "config_watcher"
    )
    tmp_dir = os.path.join(test_results_dir, "tmp")

    def path(self, *args):
        return os.path.join(self.test_dir, *args)

    @classmethod
    def runcmd(cls, *args, **kwargs):
        with cls.startcmd(*args, **kwargs) as process:
            returncode = process.wait()
            out = process.stdout.read()
            LOGGER.debug('[ret=%d]out="%s"', returncode, out.decode("utf-8"))
            if returncode:
                raise RuntimeError(f"Command {subprocess.list2cmdline(args)} failed")

    @classmethod
    def startcmd(cls, *args, **kwargs):
        if "cwd" not in kwargs:
            kwargs["cwd"] = cls.test_results_dir
        if "stdout" not in kwargs:
            kwargs["stdout"] = subprocess.PIPE
        if "stderr" not in kwargs:
            kwargs["stderr"] = subprocess.STDOUT
        LOGGER.debug("> %s", subprocess.list2cmdline(args))
        if "env" in kwargs:
            envstr = ""
            for k, v in kwargs["env"].items():
                envstr += f"{k}={v}\n"
            LOGGER.debug(">> Environment variables:\n---\n%s\n---", envstr.strip())
        return subprocess.Popen(args, **kwargs)

    def start_webhook_server(self):
        reqs = []

        class MockWebhookHandler(http.server.BaseHTTPRequestHandler):
            def store_request(self):
                payload = None
                content_length = self.headers.get("Content-Length")
                if content_length:
                    payload = self.rfile.read(int(content_length)).decode("utf-8")
                reqs.append(
                    {
                        "method": self.command,
                        "path": self.path,
                        "payload": payload,
                    }
                )
                # send OK response
                self.send_response(HTTPStatus.OK)
                self.end_headers()

            def do_GET(self):
                self.store_request()

            def do_POST(self):
                self.store_request()

            def do_PUT(self):
                self.store_request()

            def do_PATCH(self):
                self.store_request()

        server = http.server.HTTPServer(("localhost", 0), MockWebhookHandler)
        server_thread = threading.Thread(target=server.serve_forever, daemon=True)
        server_thread.start()
        self.webhook_server = server
        self.webhook_reqs = reqs
        return f"http://localhost:{server.server_address[1]}"

    def stop_webhook_server(self):
        self.webhook_server.shutdown()

    def start_watcher(self, *args, **kwargs):
        watcher_script = os.path.join(self.watcher_dir, "watcher.py")
        expect_error = False
        if "expect_error" in kwargs:
            expect_error = kwargs.pop("expect_error")
        if "env" not in kwargs:
            kwargs["env"] = dict()
        kwargs["env"].setdefault("KUBECONFIG", KUBE_CONFIG_DEFAULT_LOCATION)
        kwargs["env"].setdefault("LABEL_SELECTOR", self.TEST_LABEL_KEY)
        kwargs["env"].setdefault("TARGET_DIRECTORY", self.test_dir)
        kwargs["env"].setdefault("LOG", "DEBUG")
        self.watcher = self.startcmd(sys.executable, watcher_script, *args, **kwargs)

        try:
            returncode = self.watcher.wait(timeout=0.5)
            if not expect_error:
                # check that process is alive
                self.assertIsNone(returncode, f"Watcher failed [ret={returncode}]")
            elif isinstance(expect_error, str):
                # check the expected error string
                out = self.watcher.stdout.read()
                self.assertIn(expect_error, out.decode("utf-8"))
        except TimeoutExpired:
            if expect_error:
                self.fail("Watcher expected to fail")

    def stop_watcher(self):
        try:
            self.watcher.terminate()
            returncode = self.watcher.wait(timeout=5)
        except TimeoutExpired:
            self.watcher.kill()
            returncode = self.watcher.wait()
        out = self.watcher.stdout.read()
        self.watcher = None
        return returncode, out

    def remove_resources(self, namespace="default"):
        v1 = client.CoreV1Api()
        cm_list = v1.list_namespaced_config_map(
            namespace, label_selector=f"{self.TEST_LABEL_KEY}"
        )
        for cm in cm_list.items:
            v1.delete_namespaced_config_map(cm.metadata.name, cm.metadata.namespace)
        secrets_list = v1.list_namespaced_secret(
            namespace, label_selector=f"{self.TEST_LABEL_KEY}"
        )
        for secret in secrets_list.items:
            v1.delete_namespaced_secret(secret.metadata.name, secret.metadata.namespace)

    @classmethod
    def setUpClass(cls):
        # create test results directories
        os.makedirs(cls.test_results_dir, exist_ok=True)
        # clean and re-create tmp diretory
        shutil.rmtree(cls.tmp_dir, ignore_errors=True)
        os.makedirs(cls.tmp_dir)

    TEST_LABEL_KEY = "testLabelKey"
    TEST_LABEL_VALUE = "testLabelValue"

    def setUp(self):
        # create test tmp directory
        self.test_dir = os.path.join(self.tmp_dir, self._testMethodName)
        os.makedirs(self.test_dir)
        # configure Kubernetes client
        config.load_kube_config()
        self.watcher = None
        self.webhook_server = None
        self.webhook_reqs = None

    def tearDown(self):
        if self.watcher:
            returncode, out = self.stop_watcher()
            LOGGER.debug("Watcher [ret=%d]out=<%s>", returncode, out.decode("utf-8"))
        if self.webhook_server:
            self.stop_webhook_server()
        # delete all test ConfigMap and Secret resources
        self.remove_resources()

    def _get_labels(self, extra_labels=None):
        if extra_labels:
            return {self.TEST_LABEL_KEY: self.TEST_LABEL_VALUE, **extra_labels}
        return {self.TEST_LABEL_KEY: self.TEST_LABEL_VALUE}

    def _get_configmap(self, name, namespace="default", data={}, extra_labels=None):
        metadata = client.V1ObjectMeta(
            name=name, namespace=namespace, labels=self._get_labels(extra_labels)
        )
        return client.V1ConfigMap(
            api_version="v1", kind="ConfigMap", data=data, metadata=metadata
        )

    def _get_secret(self, name, namespace="default", data={}, extra_labels=None):
        metadata = client.V1ObjectMeta(
            name=name, namespace=namespace, labels=self._get_labels(extra_labels)
        )
        return client.V1Secret(
            api_version="v1", kind="Secret", string_data=data, metadata=metadata
        )

    def _get_namespace(self, name):
        metadata = client.V1ObjectMeta(name=name, labels=self._get_labels())
        return client.V1Namespace(api_version="v1", kind="Namespace", metadata=metadata)

    def assertFileContent(self, name, content):
        file = self.path(name)
        self.assertTrue(os.path.isfile(file), f"File {file} does not exist")
        with open(file, "r") as f:
            actual = f.read()
            self.assertEqual(content, actual, f"File {file} content differ")

    def assertFileNotExist(self, name):
        file = self.path(name)
        self.assertFalse(os.path.exists(file), f"File {file} still exists")

    def assertWebhookRequestCount(self, count, method="GET", path=None, payload=None):
        def request_matches(r):
            if r["method"] != method:
                return False
            if path and r["path"] != path:
                return False
            if payload and r["payload"] != payload:
                return False
            return True

        actual = 0
        received = "---\n"
        for req in self.webhook_reqs:
            received += f"{req}\n"
            if request_matches(req):
                actual += 1
        received += "---"
        self.assertEqual(actual, count, f"Received requests:\n{received}")

    def awaitWebhookRequestCount(
        self, count, method="GET", path=None, payload=None, timeout=5
    ):
        retry(
            lambda: self.assertWebhookRequestCount(count, method, path, payload),
            timeout,
        )

    def awaitFileContent(self, name, content, timeout=5):
        retry(lambda: self.assertFileContent(name, content), timeout)

    def awaitFileNotExist(self, name, timeout=5):
        retry(lambda: self.assertFileNotExist(name), timeout)

    def _testFilesCreated(self, resource_type):
        # start watcher
        self.start_watcher(env=dict(RESOURCE_TYPE=resource_type))
        # create Kubernetes resources
        v1 = client.CoreV1Api()
        data1 = dict(file1="content1", file2="content2")
        data2 = dict(file3="content3", file4="content4")
        if resource_type == RESOURCE_CONFIGMAP:
            cm1 = self._get_configmap(rand_str(6, "cm-"), data=data1)
            cm1 = v1.create_namespaced_config_map("default", cm1)
            cm2 = self._get_configmap(rand_str(6, "cm-"), data=data2)
            cm2 = v1.create_namespaced_config_map("default", cm2)
        else:
            s1 = self._get_secret(rand_str(6, "secret-"), data=data1)
            s1 = v1.create_namespaced_secret("default", s1)
            s2 = self._get_secret(rand_str(6, "secret-"), data=data2)
            s2 = v1.create_namespaced_secret("default", s2)
        # verify that all files are created
        for file, content in {**data1, **data2}.items():
            self.awaitFileContent(file, content)

    def testWatchForConfigMap(self):
        self._testFilesCreated(RESOURCE_CONFIGMAP)

    def testWatchForSecret(self):
        self._testFilesCreated(RESOURCE_SECRET)

    def testWatchMultipleNamespaces(self):
        v1 = client.CoreV1Api()
        # create namespaces
        namespaces = [rand_str(6, "ns-"), rand_str(6, "ns-")]
        for name in namespaces:
            ns = self._get_namespace(name)
            v1.create_namespace(ns)
        try:
            # start watcher with created namespaces
            self.start_watcher(env=dict(NAMESPACES=",".join(namespaces)))
            # create configMaps in both namespaces
            data1 = dict(file1="content1", file2="content2")
            data2 = dict(file3="content3", file4="content4")
            cm1 = self._get_configmap(
                rand_str(6, "cm-"), namespace=namespaces[0], data=data1
            )
            cm1 = v1.create_namespaced_config_map(namespaces[0], cm1)
            cm2 = self._get_configmap(
                rand_str(6, "cm-"), namespace=namespaces[1], data=data2
            )
            cm2 = v1.create_namespaced_config_map(namespaces[1], cm2)
            # verify that all files are created
            for file, content in {**data1, **data2}.items():
                self.awaitFileContent(file, content)
        finally:
            for name in namespaces:
                self.remove_resources(namespace=name)
                v1.delete_namespace(name)

    def _testWatchForChanges(self, resource_type):
        # start watcher
        self.start_watcher(env=dict(RESOURCE_TYPE=resource_type))
        v1 = client.CoreV1Api()
        data = dict(file1="content1", file2="content2")
        # create Kubernetes resources
        if resource_type == RESOURCE_CONFIGMAP:
            cm = self._get_configmap(rand_str(6, "cm-"), data=data)
            cm = v1.create_namespaced_config_map("default", cm)
        else:
            s = self._get_secret(rand_str(6, "secret-"), data=data)
            s = v1.create_namespaced_secret("default", s)
        # verify that all files are created
        for file, content in data.items():
            self.awaitFileContent(file, content)

        # update Kubernetes resources
        if resource_type == RESOURCE_CONFIGMAP:
            cm.data["file1"] = "content1_updated"
            cm = v1.replace_namespaced_config_map(cm.metadata.name, "default", cm)
        else:
            s.string_data = dict(file1="content1_updated")
            s = v1.replace_namespaced_secret(s.metadata.name, "default", s)
        # verify that the file is updated
        self.awaitFileContent("file1", "content1_updated")

        # delete the resource
        if resource_type == RESOURCE_CONFIGMAP:
            v1.delete_namespaced_config_map(cm.metadata.name, "default")
        else:
            v1.delete_namespaced_secret(s.metadata.name, "default")
        # verify that files are deleted
        for file in data:
            self.awaitFileNotExist(file)

    def testWatchForConfigMapChanegs(self):
        self._testWatchForChanges(RESOURCE_CONFIGMAP)

    def testWatchForSecretChanges(self):
        self._testWatchForChanges(RESOURCE_SECRET)

    def testWatchWithLabelSelector(self):
        # start watcher with label selector
        self.start_watcher(env=dict(LABEL_SELECTOR="foo in (value1, value2)"))
        # create several config maps
        v1 = client.CoreV1Api()
        cm1 = self._get_configmap(rand_str(6, "cm-"), data=dict(file1="content1"))
        cm1 = v1.create_namespaced_config_map("default", cm1)
        cm2 = self._get_configmap(
            rand_str(6, "cm-"),
            data=dict(file2="content2"),
            extra_labels=dict(foo="value1"),
        )
        cm2 = v1.create_namespaced_config_map("default", cm2)
        cm3 = self._get_configmap(
            rand_str(6, "cm-"),
            data=dict(file3="content3"),
            extra_labels=dict(foo="value2"),
        )
        cm3 = v1.create_namespaced_config_map("default", cm3)
        cm4 = self._get_configmap(
            rand_str(6, "cm-"),
            data=dict(file4="content4"),
            extra_labels=dict(foo="bogus"),
        )
        cm4 = v1.create_namespaced_config_map("default", cm4)
        # verify that only files in cm2 and cm3 are created
        self.awaitFileContent("file2", "content2")
        self.awaitFileContent("file3", "content3")
        self.awaitFileNotExist("file1")
        self.awaitFileNotExist("file4")

    def _testWebhookInvoked(self, method="GET"):
        # start mock webhook server
        webhook_url = self.start_webhook_server()
        webhook_path = "/test"
        webhook_payload = None

        # start watcher with webhook defined
        env = dict(WEBHOOK_METHOD=method, WEBHOOK_URL=webhook_url + webhook_path)
        if method in ["PUT", "POST", "PATCH"]:
            webhook_payload = '{"test": "test"}'
            env["WEBHOOK_PAYLOAD"] = webhook_payload
        self.start_watcher(env=env)
        # create configmap with two entries
        v1 = client.CoreV1Api()
        cm = self._get_configmap(
            rand_str(6, "cm-"), data=dict(file1="content1", file2="content2")
        )
        cm = v1.create_namespaced_config_map("default", cm)
        # validate that webhook is called
        self.awaitWebhookRequestCount(
            1, method=method, path=webhook_path, payload=webhook_payload
        )

        # update the configMap
        cm.data["file1"] = "content1_updated"
        cm.data["file2"] = "content2_updated"
        cm = v1.replace_namespaced_config_map(cm.metadata.name, "default", cm)
        # validate that webhook is called one more time
        self.awaitWebhookRequestCount(
            2, method=method, path=webhook_path, payload=webhook_payload
        )

        # delete the configMap
        v1.delete_namespaced_config_map(cm.metadata.name, cm.metadata.namespace)
        # validate that webhook is called one more time
        self.awaitWebhookRequestCount(
            3, method=method, path=webhook_path, payload=webhook_payload
        )

    def testGetWebhookInvoked(self):
        self._testWebhookInvoked("GET")

    def testPostWebhookInvoked(self):
        self._testWebhookInvoked("POST")

    def testPutWebhookInvoked(self):
        self._testWebhookInvoked("PUT")

    def testPatchWebhookInvoked(self):
        self._testWebhookInvoked("PATCH")

    def testNegativeWatcherConfig(self):
        self.start_watcher(
            env=dict(RESOURCE_TYPE="bogus"),
            expect_error="Unsupported resource type: bogus",
        )
        self.start_watcher(
            env=dict(WEBHOOK_URL="bogus"), expect_error="Invalid webhook URL: bogus"
        )
        self.start_watcher(
            env=dict(WEBHOOK_METHOD="bogus"),
            expect_error="Invalid webhook method: bogus",
        )
        self.start_watcher(
            env=dict(WEBHOOK_TIMEOUT="bogus"),
            expect_error="Invalid webhook timeout: bogus",
        )
        self.start_watcher(
            env=dict(SHUTDOWN_TIMEOUT="bogus"),
            expect_error="Invalid shutdown timeout: bogus",
        )


if __name__ == "__main__":
    unittest.main()
