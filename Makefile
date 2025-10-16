GO ?= go

.PHONY: test compose-up compose-down push-images

test:
	GOCACHE=$(PWD)/.gocache $(GO) test ./...

compose-up:
	docker compose up --build

compose-down:
	docker compose down

push-images:
	@if [ -z "$(DOCKER_USER)" ]; then \
		echo "Set DOCKER_USER=<dockerhub-username>" >&2; exit 1; \
	fi
	./scripts/build_push_all.sh $(DOCKER_USER)
