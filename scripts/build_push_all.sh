#!/usr/bin/env bash
set -euo pipefail

if [ $# -ne 1 ]; then
  echo "usage: $0 <dockerhub-username>" >&2
  exit 1
fi

DOCKERHUB_USER="$1"

build_and_push() {
  local name="$1"
  local dockerfile="$2"
  local tag="${DOCKERHUB_USER}/${name}:latest"

  echo "==> Building ${tag}"
  docker buildx build --platform linux/amd64 \
    -f "${dockerfile}" \
    -t "${tag}" \
    . --push
}

build_and_push "tailscale-identity-broker" "infra/railway/Dockerfile.broker"
build_and_push "tailscale-tool-service"     "infra/railway/Dockerfile.tool"
build_and_push "tailscale-identity-agent"   "infra/railway/Dockerfile.agent"
build_and_push "tailscale-admin-ui"         "infra/railway/Dockerfile.admin-ui"

echo "All images pushed to docker.io/${DOCKERHUB_USER}"
