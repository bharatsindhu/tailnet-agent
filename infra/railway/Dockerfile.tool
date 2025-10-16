FROM golang:1.22 AS builder
WORKDIR /app

COPY go.mod ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /tmp/tool-service ./cmd/tool-service

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    gnupg && \
    curl -fsSL https://pkgs.tailscale.com/stable/debian/bookworm.noarmor.gpg | tee /usr/share/keyrings/tailscale-archive-keyring.gpg >/dev/null && \
    curl -fsSL https://pkgs.tailscale.com/stable/debian/bookworm.tailscale-keyring.list | tee /etc/apt/sources.list.d/tailscale.list >/dev/null && \
    apt-get update && apt-get install -y --no-install-recommends tailscale && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /tmp/tool-service /usr/local/bin/tool-service
COPY infra/railway/entrypoint-tool.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENV TOOL_LISTEN_ADDR=":8090"

ENTRYPOINT ["/entrypoint.sh"]
