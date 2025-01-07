#!/bin/sh
#
# (C) Copyright 2018-2023 Dassault Systemes SE.  All Rights Reserved.

set -e

# The Docker image build creates the nuodb user ID 1000:1000. Make sure that
# the runtime user is either the same or root.
NUODB_ID=1000:1000
uid="$(id -u)"
gid="$(id -g)"
case "${uid}:${gid}" in
    (0:0|"$NUODB_ID") : ;;
    (*)
        echo "ERROR: Unexpected user and group ID: ${uid}:${gid}"
        exit 1
        ;;
esac

# Support well-known commands
case "$1" in
    (config-watcher)
        shift
        exec python3 /opt/k8s-config-watcher/watcher.py "$@"
        ;;
    (nuodb-operations)
        shift
        exec python3 /opt/nuodb-operations/backup_hooks.py server "$@"
        ;;
    (*)
        exec "$@"
        ;;
esac
