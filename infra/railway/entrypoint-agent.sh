#!/bin/sh
set -eu

if [ -z "${TAILSCALE_AUTHKEY:-}" ]; then
  echo "TAILSCALE_AUTHKEY must be set" >&2
  exit 1
fi
if [ -z "${BROKER_HOSTNAME:-}" ]; then
  echo "BROKER_HOSTNAME must be set (tailnet name of broker)" >&2
  exit 1
fi

TS_HOSTNAME=${TAILSCALE_HOSTNAME:-agent-$(hostname)}
TAILSCALE_SOCKET=${TAILSCALE_SOCKET:-/tmp/tailscaled.sock}

/usr/sbin/tailscaled --state=mem: --socket=${TAILSCALE_SOCKET} \
  --tun=userspace-networking --socks5-server=localhost:1055 \
  --outbound-http-proxy-listen=localhost:1056 &
TAILSCALED_PID=$!

cleanup() {
  kill ${TAILSCALED_PID} >/dev/null 2>&1 || true
  wait ${TAILSCALED_PID} 2>/dev/null || true
}
trap cleanup EXIT

for _ in $(seq 1 30); do
  if tailscale --socket=${TAILSCALE_SOCKET} version >/dev/null 2>&1; then
    break
  fi
  sleep 1
done

tailscale --socket=${TAILSCALE_SOCKET} up \
  --authkey=${TAILSCALE_AUTHKEY} \
  --hostname=${TS_HOSTNAME} \
  --accept-dns=false --accept-routes=true

export ALL_PROXY="socks5://127.0.0.1:1055"
export HTTPS_PROXY="socks5://127.0.0.1:1055"
export HTTP_PROXY="socks5://127.0.0.1:1055"

if [ -z "${BROKER_URL:-}" ]; then
  PORT=${BROKER_PORT:-8080}
  BROKER_URL="http://${BROKER_HOSTNAME}:${PORT}"
fi
export BROKER_URL

CMD_ARGS=${AGENT_ARGS:-"--query dana"}

set -- identity-agent --timeout=60s ${CMD_ARGS}

exec "$@"
