++ Makefile
GO ?= go
PROJECT := tailnet-identity-agent

.PHONY: bootstrap
bootstrap:
	@echo ">> installing go tools"
	@$(GO) install github.com/segmentio/golines@latest
	@$(GO) install github.com/mgechev/revive@latest
	@$(GO) install github.com/golangci/golangci-lint/cmd/golangci-lint@latest

.PHONY: lint
lint:
	@echo ">> running golangci-lint"
	@golangci-lint run ./...

.PHONY: test
test:
	@echo ">> go test ./..."
	@$(GO) test ./...

.PHONY: broker.dev
broker.dev:
	@echo ">> starting identity broker (development)"
	AUTH0_DOMAIN=$${AUTH0_DOMAIN:-https://dev.example.auth0.com} \
	AUTH0_AUDIENCE=$${AUTH0_AUDIENCE:-https://identity-broker.tailnet.local/api} \
	IDENTITY_DATA_PATH=$${IDENTITY_DATA_PATH:-infra/sample-users.json} \
	$(GO) run ./cmd/identity-broker

.PHONY: agent.run
agent.run:
	@echo ">> running agent (development)"
	BROKER_URL=$${BROKER_URL:-http://127.0.0.1:8080} \
	AUTH0_DOMAIN=$${AUTH0_DOMAIN:-https://dev.example.auth0.com} \
	AUTH0_AUDIENCE=$${AUTH0_AUDIENCE:-https://identity-broker.tailnet.local/api} \
	AUTH0_CLIENT_ID=$${AUTH0_CLIENT_ID:-dummy} \
	AUTH0_CLIENT_SECRET=$${AUTH0_CLIENT_SECRET:-dummy} \
	$(GO) run ./cmd/agent --query dana

.PHONY: docker-build
docker-build:
	@echo ">> building docker images"
	docker compose -f docker-compose.yaml build
