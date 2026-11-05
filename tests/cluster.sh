#!/bin/sh
set -eu
: "${KUBECONFIG:?Set KUBECONFIG to the dedicated test cluster explicitly}"
KUBECONFIG="$KUBECONFIG" python3 "$(dirname "$0")/cluster.py" "$@"
