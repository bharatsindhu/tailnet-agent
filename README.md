# Tailnet Identity Agent POC

> Work-in-progress portfolio project demonstrating the Tailscale Product Strategy “Software Engineer (Identity)” role requirements. This README doubles as a build log so reviewers can follow each decision.

## Current Status
- ✅ Parsed the role expectations and locked our scope around tailnet-connected AI agents.
- ✅ Confirmed Auth0 tenant details (domain `https://dev-vrh0pktpbpafzep1.us.auth0.com`, audience `https://identity-broker.tailnet.local/api`, scopes `identity:read identity:search`, client ID `cn4McqVP1BdiCGVA4MkX5sCIvH6ATEEo`).
- ✅ Implemented Go services (`identity-broker`, `agent`) with custom JWT validation (no external deps – sandbox lacks proxy access).
- ✅ Added Dockerfiles, `docker-compose.yaml`, `Makefile`, and sample identity data.
- ✅ `go test ./...` succeeds (see “Validation”).
- 🔄 Wiring documentation & deployment playbook (this README) as the build log.

## Project Overview
Goal: demonstrate the “Software Engineer (Identity) – Product Strategy” skillset by building a Tailscale-friendly AI agent that consumes identity data behind the tailnet boundary.

Deliverables:
- **Identity Broker (`cmd/identity-broker`)**: Go HTTP service running on a tailnet node, validates Auth0 RS256 access tokens (client credentials flow) and serves `/v1/identity/users` search + lookup endpoints. JWKS caching, scope enforcement, and optional roles claim handling are built in pure standard library code so we can compile offline.
- **Agent (`cmd/agent`)**: Go CLI (deployable as a long-running service) that retrieves Auth0 tokens, queries the broker over Tailscale (use `https://100.x.y.z:8080`), and optionally summarizes results with an OpenAI-compatible API. When no API key is present we fall back to deterministic summaries for testing.
- **Infra Assets**: Dockerfiles for both binaries, `docker-compose.yaml` for local rehearsal, sample identity fixtures (`infra/sample-users.json`), and a `Makefile` with lint/test/build helpers.

## Architecture Snapshot
- **Tailnet layout**
  - `identity-node` (`tag:identity-broker`): hosts the broker container, exposes port 8080, validates Auth0 JWTs, and returns identity/device metadata (static JSON or Auth0 Management API hook in future work).
  - `agent-node` (`tag:agent`): runs the agent container, fetches client-credential tokens from Auth0, and calls the broker via its Tailscale IP/FQDN.
  - **Optional**: operator laptop joins the tailnet for smoke testing via `tailscale ssh` or `curl`.

- **Request flow**
  1. Agent receives a user query (CLI flag or scheduled job).
  2. Agent exchanges client credentials with Auth0 (`identity:read identity:search` scopes).
  3. Agent calls `GET /v1/identity/users` (search) or `GET /v1/identity/users/{id}` (lookup) across the tailnet using Tailscale IPs.
  4. Broker validates JWT signature against Auth0 JWKS, checks issuer/audience, enforces scopes, and returns identity data.
  5. Agent formats/summarizes the response (LLM-backed when configured) and prints/logs results or forwards to downstream tooling (future: MCP registry, Slack notifier).

- **Repository map**
  - `cmd/identity-broker`: HTTP server, Auth0 validation middleware, static identity provider.
  - `cmd/agent`: CLI entrypoint, Auth0 client credentials exchange, broker integrations.
  - `internal/auth0`: lightweight JWT + JWKS helpers (standard library only).
  - `internal/identity`: identity provider interfaces, static JSON loader, unit tests.
  - `internal/agent`: summarizer abstraction + OpenAI-compatible client.
  - `infra/`: Dockerfiles, sample data, future ACL/systemd snippets.

## Quick Start (Local)
```bash
make test                                   # go test ./...
AUTH0_DOMAIN=https://dev-vrh0pktpbpafzep1.us.auth0.com \
AUTH0_AUDIENCE=https://identity-broker.tailnet.local/api \
IDENTITY_DATA_PATH=infra/sample-users.json \
go run ./cmd/identity-broker                # local broker on :8080

# In another shell (same env plus client credentials):
BROKER_URL=http://127.0.0.1:8080 \
AUTH0_CLIENT_ID=cn4McqVP1BdiCGVA4MkX5sCIvH6ATEEo \
AUTH0_CLIENT_SECRET=<redacted> \
go run ./cmd/agent --query dana             # search demo
```

If you’d rather containerise:
```bash
AUTH0_DOMAIN=... AUTH0_AUDIENCE=... \
AUTH0_CLIENT_ID=... AUTH0_CLIENT_SECRET=... \
docker compose up --build
```
The compose file links agent → broker internally. Replace secrets with your actual values.

## Tailnet Deployment Playbook
1. **Provision nodes**
   - `identity-node`: Linux VM (cloud or bare metal) with Docker/Go, join tailnet with tag `tag:identity-broker`.
   - `agent-node`: Linux VM, join tailnet with tag `tag:agent`.
   - Create/approve ACL entries (see future `infra/acl.json`) allowing `tag:agent` → `tag:identity-broker:8080` and granting Tailscale SSH access to ops roles.

2. **Ship binaries**
   - Build locally (`make build` TODO or use Dockerfiles) and copy to nodes via `tailscale ssh <node> -- sudo install ...`.
   - Or push container images to a registry, then pull on nodes.

3. **Configure environment**
   - Both nodes need `AUTH0_DOMAIN`, `AUTH0_AUDIENCE`.
   - Agent node additionally needs `AUTH0_CLIENT_ID`, `AUTH0_CLIENT_SECRET`, `AUTH0_SCOPES`, and (optional) `OPENAI_API_KEY`.
   - Broker node needs `IDENTITY_DATA_PATH` (default static JSON) and optional `AUTH0_ROLES_CLAIM` (e.g. `https://tailscale.example/roles`).

4. **Run services**
   - Broker: `IDENTITY_DATA_PATH=/opt/tailscale/sample-users.json AUTH0_... ./identity-broker`.
   - Agent: `BROKER_URL=https://100.x.y.z:8080 AUTH0_... ./agent --user auth0|123`.
   - Wrap both in `systemd` units (to be added under `infra/`) for persistence and logging.

5. **Validate**
   - From agent node: `curl -H "Authorization: Bearer $(./agent --print-token)" https://100.x.y.z:8080/v1/identity/users`.
   - Observe broker logs (JSON) for scope enforcement and request IDs.

## Auth0 Configuration Recap
- API: `Tailnet Identity Broker`, audience `https://identity-broker.tailnet.local/api`, algorithm RS256, scopes `identity:read`, `identity:search`, RBAC enabled.
- Machine-to-Machine App: `Tailnet Agent Service`, authorised for above API + scopes.
- Optional action to project roles into access tokens via custom claim (reflected with `AUTH0_ROLES_CLAIM` env).

## Validation
- `GOCACHE=$(pwd)/.gocache go test ./...`
  ```
  ok   github.com/tailscale-portfolio/identity-agent-poc/internal/identity  0.20s
  ```
- Manual smoke tests: local `go run` broker + agent (with dummy Auth0 response) and static summariser fallback.

## Next Steps / Backlog
- 🔜 Wire Auth0 Management API integration (swap static provider when `AUTH0_MGMT_CLIENT_*` present).
- 🔜 Produce Tailnet ACL snippet + `systemd` units under `infra/`.
- 🔜 Add MCP gateway manifest so the agent can expose identity tools to other frameworks.
- 🔜 Extend test coverage (JWT validator, agent HTTP client) and add GitHub Actions workflow.
- 🔜 Capture architecture diagram (`docs/architecture.png`) once implementation stabilises.

I’ll keep updating this README as new pieces land. Ping me if you want a deeper dive into deployment automation, management API hooks, or MCP gateway design. 
