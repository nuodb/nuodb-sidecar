#!/usr/bin/env python

import os
import sys
import logging
from urllib.parse import urlparse
from hashlib import sha256
import base64
import traceback
import time
from threading import Thread
import queue

from kubernetes import client, config, watch
from kubernetes.client import ApiException
from kubernetes.config.kube_config import KUBE_CONFIG_DEFAULT_LOCATION

from urllib3.util.retry import Retry
from urllib3.exceptions import MaxRetryError, HTTPError, TimeoutError

import requests
from requests.adapters import HTTPAdapter

logging.basicConfig(level=logging.DEBUG, format="%(asctime)s %(levelname)s %(message)s")
LOGGER = logging.getLogger(__name__)

RESOURCE_CONFIGMAP = "config_map"
RESOURCE_SECRET = "secret"

NAMESPACES = os.environ.get("NAMESPACES")
LABEL_SELECTOR = os.environ.get("LABEL_SELECTOR", os.environ.get("LABEL"))
TARGET_DIRECTORY = os.environ.get("TARGET_DIRECTORY", os.environ.get("FOLDER"))
RESOURCE_TYPE = os.environ.get("RESOURCE_TYPE", RESOURCE_CONFIGMAP)
WATCH_TIMEOUT = os.environ.get("WATCH_TIMEOUT", "60")

WEBHOOK_URL = os.environ.get("WEBHOOK_URL", os.environ.get("REQ_URL"))
WEBHOOK_METHOD = os.environ.get("WEBHOOK_METHOD", "GET")
WEBHOOK_PAYLOAD = os.environ.get("WEBHOOK_PAYLOAD")
WEBHOOK_TIMEOUT = os.environ.get("WEBHOOK_TIMEOUT", "60")
WEBHOOK_VERIFY = os.environ.get("WEBHOOK_VERIFY", "true")

NAMESPACE_FILE = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"
DEFAULT_RETRIES = Retry(connect=5, read=5, backoff_factor=0.5)

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
            raise RuntimeError(f"Target path {TARGET_DIRECTORY} exists and is not directory")
    else:
        os.mkdir(TARGET_DIRECTORY)
    if RESOURCE_TYPE not in [RESOURCE_CONFIGMAP, RESOURCE_SECRET]:
        raise RuntimeError(f"Unsupported resource type {RESOURCE_TYPE}")
    if WEBHOOK_URL is not None:
        try:
            urlparse(WEBHOOK_URL)
        except Exception as e:
            raise RuntimeError(f"Invalid webhook URL {WEBHOOK_URL}") from e
    if WEBHOOK_METHOD not in ['GET', 'POST', 'PUT', 'PATCH']:
        raise RuntimeError(f"Invalid webhook method {WEBHOOK_METHOD}")

def load_kube_config():
    namespaces = []
    if NAMESPACES is not None:
        for ns in NAMESPACES.split(","):
            namespaces.append(ns)
    try:
        config.load_kube_config(config_file=KUBE_CONFIG_DEFAULT_LOCATION)
        logging.debug("Configuration from '%s' file laoded", KUBE_CONFIG_DEFAULT_LOCATION)
    except Exception:
        config.load_incluster_config()
        logging.debug("In-cluster configuration loaded")
        # Load the includer namespace
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
    mode = "w"
    if isinstance(content, (bytes, bytearray)):
        mode += "b"

    # Compare with old file content by calculating SHA256 hash
    if os.path.isfile(path):
        if 'b' in mode:
            hash_new = sha256(content)
        else:
            hash_new = sha256(content.encode('utf-8'))
        with open(path, 'rb') as f:
            hash_cur = sha256()
            for byte_block in iter(lambda: f.read(4096), b""):
                hash_cur.update(byte_block)
        if hash_new.hexdigest() == hash_cur.hexdigest():
            return False

    with open(path, mode) as f:
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
            LOGGER.warning("Failed to process resource %s/%s data key={key}: %s",
                            metadata.namespace, metadata.name, e)
    return changed

def invoke_webhook(metadata):
    session = requests.Session()
    session.mount("http://", HTTPAdapter(max_retries=DEFAULT_RETRIES))
    session.mount("https://", HTTPAdapter(max_retries=DEFAULT_RETRIES))
    LOGGER.info("Invoking webhook after %s/%s resource change\n -> %s %s",
                metadata.namespace, metadata.name, WEBHOOK_METHOD, WEBHOOK_URL)
    resp = session.request(WEBHOOK_METHOD, WEBHOOK_URL, data=WEBHOOK_PAYLOAD,
                    timeout=int(WEBHOOK_TIMEOUT), verify=WEBHOOK_VERIFY.lower()=="true")
    LOGGER.info("Webhook response\n <- %s %s %s %s",
                resp.status_code, WEBHOOK_METHOD, WEBHOOK_URL, resp.text)



class ConfigWatcher:
    def __init__(self, resource, namespace, label_selector,
                 request_timeout=60, watch_timeout=60):
        self.resource = resource
        self.namespace = namespace
        self.label_selector = label_selector
        self.request_timeout = request_timeout
        self.watch_timeout = watch_timeout
        self.stopped = False
        self.watch = watch.Watch()

    def start(self):
        while not self.stopped:
            try:
                LOGGER.debug("Watching %s resources in namespace %s with selector '%s'",
                            self.resource, self.namespace, self.label_selector)
                self.do_watch()
            except ApiException as e:
                LOGGER.warning("Kubernetes API server error: %s", e)
                time.sleep(5)
            except TimeoutError as e:
                LOGGER.debug("Timeout while reading from API server: %s", e)
            except MaxRetryError as e:
                LOGGER.error("Max retried exausted calling API server: %s", e)
                raise
            except HTTPError as e:
                LOGGER.error("HTTP error while calling API server: %s", e)
                raise

    def stop(self):
        self.stopped = True
        if self.watch:
            self.watch.stop()

    def do_watch(self):
        kwargs = {
            'namespace': self.namespace,
            'label_selector': self.label_selector,
            'timeout_seconds': self.watch_timeout,
            '_request_timeout': self.request_timeout,
        }
        list_func = getattr(client.CoreV1Api(), f"list_namespaced_{self.resource}")
        for event in self.watch.stream(list_func, **kwargs):
            event_type = event['type']
            event_object = event['object']
            metadata = event_object.metadata
            LOGGER.debug("Received %s event for %s %s/%s",
                         event_type, event_object.kind, metadata.namespace, metadata.name)
            resource_removed = event_type == 'DELETED'
            changed = process_resource_data(event_object.metadata, event_object.data,
                                            remove=resource_removed)
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

def start_watchers(namespaces):
    threads = []
    exc_queue = queue.Queue()
    try:
        # Start a config watcher thread per namespace
        for ns in namespaces:
            thread = NamespaceWatcherThread(RESOURCE_TYPE, ns, LABEL_SELECTOR, exc_queue,
                                            watch_timeout=int(WATCH_TIMEOUT))
            thread.start()
            threads.append(thread)
        # Wait for watchers
        exc = exc_queue.get()
        if exc is not None:
            raise exc
    except BaseException:
        # Stop all threads
        stop_watchers(threads)

def stop_watchers(threads, timeout=2):
    for t in threads:
        t.stop()
    # Wait for all threads to stop
    start_time = time.time()
    while len(threads) > 0:
        t = threads.pop(0)
        t.join(0.1)
        if t.is_alive():
            threads.append(t)
        if time.time() - start_time > timeout:
            raise

def main():
    validate_environment()
    namespaces = load_kube_config()
    try:
        start_watchers(namespaces)
    except KeyboardInterrupt:
        LOGGER.info("Exiting due to interrupt...")
        sys.exit(1)
    except Exception:
        traceback.print_exc(file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
