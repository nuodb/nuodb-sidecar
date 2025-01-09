#!/bin/sh

: ${TMP_DIR:="/tmp"}
: ${KWOK_WORKDIR:="$TMP_DIR/kwok"}
export KWOK_WORKDIR

kwokctl delete cluster