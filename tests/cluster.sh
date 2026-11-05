#!/bin/sh
set -eu
# Never inherit an unrelated context.
KUBECONFIG=~/.kube/talos python3 "$(dirname "$0")/cluster.py" "$@"
