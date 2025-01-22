#!/bin/sh
#
# (C) Copyright 2018-2025 Dassault Systemes SE.  All Rights Reserved.

set -e

# The Docker image build creates the nuodb user ID 1000:0, but the runtime user
# can have any arbitrary user ID. In OpenShift specifically, the runtime user
# ID is chosen by the environment. If the runtime user is not root or the
# build-time nuodb and has either gid 0 or uid 1000, use nss_wrapper to
# dynamically create an entry for the nuodb user with the actual uid and gid.
NUODB_DEFAULT_UID=1000
uid="$(id -u)"
gid="$(id -g)"
case "${uid}:${gid}" in
    (0:0|"$NUODB_DEFAULT_UID":0) : ;;
    (*:0|"$NUODB_DEFAULT_UID":*)
        # Check if /tmp is writable
        if test -w /tmp/passwd; then
            # Replace uid:gid for nuodb user
            sed "s/^nuodb:x:${NUODB_DEFAULT_UID}:0:/nuodb:x:${uid}:${gid}:/" /etc/passwd.nuodb > /tmp/passwd

            # Copy /etc/group and add nuodb group if necessary
            cp /etc/group /tmp/group
            if [ "$gid" != 0 ]; then
                echo "nuodb:x:${gid}:" >> /tmp/group
            fi

            # Enable nss_wrapper
            export LD_PRELOAD=libnss_wrapper.so
            export NSS_WRAPPER_PASSWD=/tmp/passwd
            export NSS_WRAPPER_GROUP=/tmp/group
        fi
        ;;
    (*)
        echo "ERROR: Unexpected user and group ID: ${uid}:${gid}"
        exit 1
        ;;
esac

# Configure shell
. /home/nuodb/.profile

# Support well-known commands
case "$1" in
    (config_watcher)
        shift
        exec python3 /opt/config_watcher/watcher.py "$@"
        ;;
    (nuodb-operations)
        shift
        exec python3 /opt/nuodb-operations/backup_hooks.py server "$@"
        ;;
    (*)
        exec "$@"
        ;;
esac
