#!/bin/sh
set -eu

if [ -z "${TAILSCALE_AUTHKEY:-}" ]; then
  echo "TAILSCALE_AUTHKEY must be set" >&2
  exit 1
fi
required_env="AUTH0_DOMAIN AUTH0_CLIENT_ID AUTH0_CLIENT_SECRET AUTH0_REDIRECT_URI AUTH0_AUDIENCE AUTH0_M2M_CLIENT_ID AUTH0_M2M_CLIENT_SECRET BROKER_URL TOOL_SERVICE_URL SESSION_SECRET"
for var in $required_env; do
  eval val="\${$var:-}"
  if [ -z "$val" ]; then
    echo "$var must be set" >&2
    exit 1
  fi
done

TS_HOSTNAME=${TAILSCALE_HOSTNAME:-admin-ui-$(hostname)}
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

# Proxy :80 to the admin UI (:8100)
tailscale --socket=${TAILSCALE_SOCKET} serve --bg --http=80 http://127.0.0.1:8100

export ALL_PROXY="socks5://127.0.0.1:1055"
export HTTPS_PROXY="socks5://127.0.0.1:1055"
export HTTP_PROXY="socks5://127.0.0.1:1055"

exec admin-ui
