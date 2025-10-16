#!/bin/sh
set -eu

if [ -z "${TAILSCALE_AUTHKEY:-}" ]; then
  echo "TAILSCALE_AUTHKEY must be set" >&2
  exit 1
fi
if [ -z "${AUTH0_DOMAIN:-}" ] || [ -z "${AUTH0_AUDIENCE:-}" ]; then
  echo "AUTH0_DOMAIN and AUTH0_AUDIENCE must be set" >&2
  exit 1
fi

TS_HOSTNAME=${TAILSCALE_HOSTNAME:-tool-$(hostname)}
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

exec tool-service
