# Deploying Broker, Tool Service, Agent & Admin UI on Railway

This guide shows how to run every component of the Tailnet Identity Agent POC on Railway using the Docker images you push to Docker Hub. Each service joins your tailnet via Tailscale and communicates with the others over MagicDNS.

## Prerequisites

- Railway account (free tier is fine, but services restart frequently—use **ephemeral + reusable** Tailscale auth keys).
- Four Tailscale auth keys tagged `tag:identity-broker`, `tag:tool-service`, `tag:agent`, and `tag:admin-ui`.
- Tailnet ACL permitting `tag:agent` and `tag:admin-ui` to reach:
  - `tag:identity-broker:8080`
  - `tag:tool-service:8090`
- Auth0 tenant configured as described in `docs/auth0-config.md`.
- Docker Hub account (adjust commands if you prefer another registry).

Environment templates live in `infra/railway/env-samples/`; copy each `*.env.example` when populating Railway variables.

---

## 1. Build & Push Images

From the repo root:

```bash
scripts/build_push_all.sh <dockerhub-username>
```

This pushes:

- `tailscale-identity-broker`
- `tailscale-tool-service`
- `tailscale-identity-agent`
- `tailscale-admin-ui`

Each Railway service will reference these pre-built images.

---

## 2. Generate Auth Keys & Update ACLs

In the Tailscale admin console create four **ephemeral, reusable** keys (one per tag) and update your ACL. Example:

```json
{
  "tagOwners": {
    "tag:identity-broker": ["you@example.com"],
    "tag:tool-service": ["you@example.com"],
    "tag:agent": ["you@example.com"],
    "tag:admin-ui": ["you@example.com"]
  },
  "acls": [
    {
      "action": "accept",
      "users": ["tag:agent", "tag:admin-ui"],
      "ports": ["tag:identity-broker:8080", "tag:tool-service:8090"]
    }
  ]
}
```

---

## 3. Create Railway Services

For each component choose **New Service → Deploy Docker Image** and set the image to `docker.io/<dockerhub-user>/<image>:latest`. Use the matching env template for variables.

1. **Identity Broker**
   - Image: `tailscale-identity-broker`
   - Env template: `infra/railway/env-samples/broker.env.example`
   - Joins the tailnet and listens on `8080` (no public port).

2. **Tool Service**
   - Image: `tailscale-tool-service`
   - Env template: `infra/railway/env-samples/tool-service.env.example`
   - Validates tokens with the `tool.access:grant` scope and records grants.

3. **Agent**
   - Image: `tailscale-identity-agent`
   - Env template: `infra/railway/env-samples/agent.env.example`
   - Set `AGENT_ARGS` (e.g. `--grant-group developers`). The container runs once and exits after completing the command.

4. **Admin UI**
   - Image: `tailscale-admin-ui`
   - Env template: `infra/railway/env-samples/admin-ui.env.example`
   - Entry point proxies port `80` to the internal UI (`:8100`); visit `http://admin-ui.<tailnet-domain>/` from a tailnet device.

After each deploy check the logs for `active login: …` to confirm the service joined your tailnet.

---

## 4. Verify the Demo

1. **Broker health** – `curl http://identity-broker.<tailnet-domain>:8080/healthz`
2. **Tool health** – `curl http://tool-service.<tailnet-domain>:8090/healthz`
3. **Agent** – Redeploy with `AGENT_ARGS="--grant-group developers"` (and adjust `AGENT_GRANT_PERMISSIONS` if desired) and confirm the logs show successful grants.
4. **Admin UI** – Open `http://admin-ui.<tailnet-domain>/`, sign in via Auth0, click “Grant access,” then check `http://tool-service...:8090/access/list` for the new records.

---

## Troubleshooting

- **Auth key expired** – Ensure the key is set to “Ephemeral” and “Reusable” before redeploying.
- **DNS failures** – Use the exact MagicDNS names shown in `tailscale status` (Railway often appends numeric suffixes).
- **Auth0 401/403** – Double-check audience, scopes (`identity:read identity:search tool.access:grant`), and client credentials.
- **Admin UI callback mismatch** – `AUTH0_REDIRECT_URI` must match the HTTP URL (`http://admin-ui.../callback`).
- **Agent missing from Machines list** – Expected; it terminates after each run. Redeploy when you need a fresh invocation.

With all four services running you have a full demonstration: the admin UI and agent call the broker for identity data, grant Tool X permissions via the tool service, and everything travels across your tailnet using Tailscale.
