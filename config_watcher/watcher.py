#!/usr/bin/env python

import os
import sys
import logging
from urllib.parse import urlparse
import base64
import traceback
import time
from threading import Thread
import queue

from kubernetes import client, config, watch
from kubernetes.client import ApiException
from kubernetes.config.kube_config import KUBE_CONFIG_DEFAULT_LOCATION

from urllib3.util.retry import Retry
from urllib3.exceptions import (
    MaxRetryError,
    HTTPError,
    TimeoutError as UrlLibTimeoutError,
)

import requests
from requests.adapters import HTTPAdapter

LOG = os.environ.get("LOG", "INFO")
logging.basicConfig(level=LOG.upper(), format="%(asctime)s %(levelname)s %(message)s")
LOGGER = logging.getLogger(__name__)

RESOURCE_CONFIGMAP = "config_map"
RESOURCE_SECRET = "secret"

NAMESPACES = os.environ.get("NAMESPACES")
LABEL_SELECTOR = os.environ.get("LABEL_SELECTOR", os.environ.get("LABEL"))
TARGET_DIRECTORY = os.environ.get("TARGET_DIRECTORY", os.environ.get("FOLDER"))
RESOURCE_TYPE = os.environ.get("RESOURCE_TYPE", RESOURCE_CONFIGMAP)
WATCH_TIMEOUT = os.environ.get("WATCH_TIMEOUT", "60")
SHUTDOWN_TIMEOUT = os.environ.get("SHUTDOWN_TIMEOUT", "0")

WEBHOOK_URL = os.environ.get("WEBHOOK_URL", os.environ.get("REQ_URL"))
WEBHOOK_METHOD = os.environ.get("WEBHOOK_METHOD", "GET")
WEBHOOK_PAYLOAD = os.environ.get("WEBHOOK_PAYLOAD")
WEBHOOK_TIMEOUT = os.environ.get("WEBHOOK_TIMEOUT", "60")
WEBHOOK_VERIFY = os.environ.get("WEBHOOK_VERIFY", "true")

NAMESPACE_FILE = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"
RETRY_COUNT = 5
DEFAULT_RETRIES = Retry(
    connect=RETRY_COUNT,
    read=RETRY_COUNT,
    total=RETRY_COUNT,
    backoff_factor=0.5,
)


def validate_environment():
    # Validate mandatory config
    mandatory = []
    if LABEL_SELECTOR is None:
        mandatory.append("LABEL_SELECTOR")
    if TARGET_DIRECTORY is None:
        mandatory.append("TARGET_DIRECTORY")
    if len(mandatory) > 0:
        raise RuntimeError(f"Mandatory configuration options: {', '.join(mandatory)}")
    if os.path.exists(TARGET_DIRECTORY):
        if not os.path.isdir(TARGET_DIRECTORY):
            raise RuntimeError(
                f"Target path {TARGET_DIRECTORY} exists and is not directory"
            )
    else:
        os.mkdir(TARGET_DIRECTORY)
    if RESOURCE_TYPE not in [RESOURCE_CONFIGMAP, RESOURCE_SECRET]:
        raise RuntimeError(f"Unsupported resource type: {RESOURCE_TYPE}")
    if WEBHOOK_URL is not None:
        try:
            result = urlparse(WEBHOOK_URL)
            if not result.scheme or not result.netloc:
                raise RuntimeError("schema or location missing")
        except Exception as e:
            raise RuntimeError(f"Invalid webhook URL: {WEBHOOK_URL}") from e
    if WEBHOOK_METHOD not in ["GET", "POST", "PUT", "PATCH"]:
        raise RuntimeError(f"Invalid webhook method: {WEBHOOK_METHOD}")
    for k, v in {
        "shutdown timeout": SHUTDOWN_TIMEOUT,
        "webhook timeout": WEBHOOK_TIMEOUT,
    }.items():
        try:
            float(v)
        except ValueError as e:
            raise RuntimeError(f"Invalid {k}: {v}") from e


def load_kube_config():
    namespaces = []
    if NAMESPACES is not None:
        for ns in NAMESPACES.split(","):
            namespaces.append(ns)
    try:
        config.load_kube_config(config_file=KUBE_CONFIG_DEFAULT_LOCATION)
        LOGGER.debug(
            "Configuration from '%s' file loaded", KUBE_CONFIG_DEFAULT_LOCATION
        )
    except Exception:
        # Load in-cluster configuration
        config.load_incluster_config()
        LOGGER.debug("In-cluster configuration loaded")
        if len(namespaces) == 0 and os.path.isfile(NAMESPACE_FILE):
            with open(NAMESPACE_FILE) as f:
                namespaces.append(f.read())
    configuration = client.Configuration.get_default_copy()
    # Retry Kubernetes client requests
    configuration.retries = DEFAULT_RETRIES
    # Set default namespace
    if len(namespaces) == 0:
        namespaces.append("default")
    LOGGER.info("Connecting to API server '%s'", configuration.host)
    client.Configuration.set_default(configuration)
    return namespaces


def update_file(path, content, remove=False):
    if remove:
        # Remove the file if exist
        if os.path.exists(path):
            os.remove(path)
            return True
        return False
    if not isinstance(content, (bytes, bytearray)):
        content = content.encode("utf-8")

    # Compare with current file contents
    if os.path.isfile(path):
        with open(path, "rb") as f:
            content_cur = f.read()
        if content_cur == content:
            return False

    with open(path, "wb") as f:
        # Write the content, flush buffers and invoke fsync() to make sure data
        # is written to disk
        f.write(content)
        f.flush()
        os.fsync(f.fileno())
    # Make sure that file is accessible by nuodb user, which has uid 1000 by
    # default. Making the file group-writable ensures that it is accessible to
    # the nuodb user in OpenShift deployments where an arbitrary uid is used
    # with gid 0.
    if os.getuid() == 0:
        os.chown(path, 1000, 0)
        os.chmod(path, mode=0o660)
    return True


def process_resource_data(metadata, data, remove=False):
    changed = False
    for key in data.keys():
        file_path = os.path.join(TARGET_DIRECTORY, key)
        try:
            content = data[key]
            if RESOURCE_TYPE == RESOURCE_SECRET:
                content = base64.b64decode(content)
            if update_file(file_path, content, remove):
                action = "updated"
                if remove:
                    action = "removed"
                LOGGER.info("File %s content %s", file_path, action)
                changed = True
        except Exception as e:
            LOGGER.warning(
                "Failed to process resource %s/%s data key=%s: %s",
                metadata.namespace,
                metadata.name,
                key,
                e,
            )
    return changed


def invoke_webhook(metadata):
    session = requests.Session()
    session.mount("http://", HTTPAdapter(max_retries=DEFAULT_RETRIES))
    session.mount("https://", HTTPAdapter(max_retries=DEFAULT_RETRIES))
    LOGGER.info(
        "Invoking webhook after %s/%s resource change\n -> %s %s",
        metadata.namespace,
        metadata.name,
        WEBHOOK_METHOD,
        WEBHOOK_URL,
    )
    resp = session.request(
        WEBHOOK_METHOD,
        WEBHOOK_URL,
        data=WEBHOOK_PAYLOAD,
        timeout=int(WEBHOOK_TIMEOUT),
        verify=WEBHOOK_VERIFY.lower() == "true",
    )
    LOGGER.info(
        "Webhook response\n <- %s %s %s %s",
        resp.status_code,
        WEBHOOK_METHOD,
        WEBHOOK_URL,
        resp.text,
    )


class ConfigWatcher:
    def __init__(
        self,
        resource,
        namespace,
        label_selector,
        request_timeout=60,
        watch_timeout=60,
        retry=5,
        retry_delay=5.0,
    ):
        self.resource = resource
        self.namespace = namespace
        self.label_selector = label_selector
        self.request_timeout = request_timeout
        self.watch_timeout = watch_timeout
        self.retry = retry
        self.retry_delay = retry_delay
        self.stopped = False
        self.watch = watch.Watch()

    def start(self):
        while not self.stopped:
            try:
                LOGGER.debug(
                    "Watching %s resources in namespace '%s' with selector '%s'",
                    self.resource,
                    self.namespace,
                    self.label_selector,
                )
                self.do_watch()
            except ApiException as e:
                if e.status != 500:
                    LOGGER.warning("Kubernetes API server error: %s", e)
                    self._check_retry_exhausted(e)
                else:
                    raise
            except UrlLibTimeoutError as e:
                LOGGER.debug("Timeout while reading from API server: %s", e)
            except MaxRetryError as e:
                # the request has been already retired by urllib3
                LOGGER.error("Max retries exhausted calling API server: %s", e)
                raise
            except HTTPError as e:
                LOGGER.error("HTTP error while calling API server: %s", e)
                self._check_retry_exhausted(e)

    def stop(self):
        self.stopped = True
        if self.watch:
            self.watch.stop()

    def _check_retry_exhausted(self, err):
        if self.retry < 0:
            raise err
        self.retry -= 1
        time.sleep(self.retry_delay)

    def do_watch(self):
        kwargs = {
            "namespace": self.namespace,
            "label_selector": self.label_selector,
            "timeout_seconds": self.watch_timeout,
            "_request_timeout": self.request_timeout,
        }
        list_func = getattr(client.CoreV1Api(), f"list_namespaced_{self.resource}")
        for event in self.watch.stream(list_func, **kwargs):
            event_type = event["type"]
            event_object = event["object"]
            metadata = event_object.metadata
            LOGGER.debug(
                "Received %s event for %s %s/%s",
                event_type,
                event_object.kind,
                metadata.namespace,
                metadata.name,
            )
            resource_removed = event_type == "DELETED"
            changed = process_resource_data(
                event_object.metadata, event_object.data, remove=resource_removed
            )
            if changed and WEBHOOK_URL is not None:
                try:
                    invoke_webhook(event_object.metadata)
                except Exception as e:
                    LOGGER.warning("Failed to invoke webhook: %s", e)
            if self.stopped:
                return


class NamespaceWatcherThread(Thread):
    def __init__(self, resource, namespace, selector, exc_queue, **kwargs):
        Thread.__init__(self, name=f"{namespace} watcher", daemon=True)
        self.namespace = namespace
        self.watcher = ConfigWatcher(resource, namespace, selector, **kwargs)
        self.exc_queue = exc_queue

    def run(self):
        try:
            self.watcher.start()
        except Exception as e:
            LOGGER.error("Failed to watch %s namespace: %s", self.namespace, e)
            self.exc_queue.put(e)
            raise

    def stop(self):
        LOGGER.info("Stopping config watcher for %s namespace", self.namespace)
        self.watcher.stop()


def start_watchers(
    namespaces,
    exc_queue,
    resource_type=RESOURCE_TYPE,
    label_selector=LABEL_SELECTOR,
    watch_timeout=int(WATCH_TIMEOUT),
    retry=RETRY_COUNT,
):
    threads = []
    for ns in namespaces:
        # Start a config watcher thread per namespace
        thread = NamespaceWatcherThread(
            resource_type,
            ns,
            label_selector,
            exc_queue,
            watch_timeout=watch_timeout,
            retry=retry,
        )
        thread.start()
        threads.append(thread)
    return threads


def watch_namespaces(namespaces):
    threads = None
    try:
        # Start all watchers
        exc_queue = queue.Queue()
        threads = start_watchers(namespaces, exc_queue)
        # Block until at least one watcher dies
        exc = exc_queue.get()
        if exc is not None:
            raise exc
    except:
        # Stop all threads
        stop_watchers(threads, timeout=float(SHUTDOWN_TIMEOUT))
        raise


def stop_watchers(threads, timeout=5):
    for t in threads:
        t.stop()
    # Wait for all threads to stop
    start_time = time.time()
    while len(threads) > 0:
        t = threads.pop(0)
        t.join(0.1)
        if t.is_alive():
            threads.append(t)
        elapsed = time.time() - start_time
        if elapsed > timeout:
            if timeout > 0:
                LOGGER.debug(
                    "%d watcher threads still running after %.2fs",
                    len(threads),
                    elapsed,
                )
            return


def main():
    validate_environment()
    try:
        namespaces = load_kube_config()
        watch_namespaces(namespaces)
    except KeyboardInterrupt:
        LOGGER.info("Exiting due to interrupt...")
        sys.exit(1)
    except Exception:
        traceback.print_exc(file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
