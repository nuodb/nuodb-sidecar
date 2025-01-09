#!/bin/sh

set -e

: ${TMP_DIR:="/tmp"}
: ${KWOK_WORKDIR:="$TMP_DIR/kwok"}
export KWOK_WORKDIR

: ${KUBECONFIG:="$TMP_DIR/kubeconfig.yaml"}
export KUBECONFIG

echo "Creating K8s cluster..."
kwokctl create cluster --wait 1m

CLUSTER_DIR="$KWOK_WORKDIR/clusters/kwok"
DOCKER_NET="kwok-kwok"

chmod -R a+X,a+r "$CLUSTER_DIR"

cat <<EOF
Setup complete.

To inspect Kubernetes state:

  export KUBECONFIG="$KUBECONFIG"
  kubectl get nodes
EOF
