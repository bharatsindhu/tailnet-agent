# Auth0 Configuration Reference

This project uses one Auth0 API and two Auth0 applications. The table below summarizes what each service needs.

| Component      | Purpose                      | Auth0 Entity                | Required Scopes                                       | Notes |
|----------------|------------------------------|-----------------------------|-------------------------------------------------------|-------|
| **Identity Broker API** | Protects `/v1/identity` endpoints | API (`Tailnet Identity Broker`) | `identity:read`, `identity:search`, `tool.access:grant` | Audience: `https://identity-broker.tailnet.local/api` |
| **Agent & Admin UI backend (M2M)** | Client credentials flow to call broker & tool service | Machine-to-Machine Application (`Tailnet Agent Service`) | same as API (`identity:read identity:search tool.access:grant`) | Client ID/Secret exported as `AUTH0_CLIENT_ID` / `AUTH0_CLIENT_SECRET` (agent) and `AUTH0_M2M_CLIENT_ID` / `AUTH0_M2M_CLIENT_SECRET` (admin UI) |
| **Admin UI front-end (OIDC login)** | End-user login (Authorization Code flow) | Regular Web App (`Tailnet Admin UI`) | `openid profile email` | Callback: `http://admin-ui.<tailnet-domain>/callback`; web origin/logout set to same domain. |

## Step-by-step Setup

1. **Create the API**
   - Name: `Tailnet Identity Broker`
   - Identifier: `https://identity-broker.tailnet.local/api`
   - Signing Algorithm: RS256
   - Enable RBAC + “Add Permissions in the Access Token”
   - Define scopes: `identity:read`, `identity:search`, `tool.access:grant`

2. **Create the Machine-to-Machine Application**
   - Name: `Tailnet Agent Service`
   - Type: Machine to Machine
   - Authorize against the API above and grant all three scopes
   - Copy the client ID/secret for environment variables:
     - Agent: `AUTH0_CLIENT_ID`, `AUTH0_CLIENT_SECRET`, `AUTH0_SCOPES`
     - Admin UI backend: `AUTH0_M2M_CLIENT_ID`, `AUTH0_M2M_CLIENT_SECRET`

3. **Create the Regular Web App**
   - Name: `Tailnet Admin UI`
   - Type: Regular Web Application
   - Allowed Callback URLs: `http://admin-ui.<tailnet-domain>/callback`
   - Allowed Logout URLs: `http://admin-ui.<tailnet-domain>/`
   - Allowed Web Origins: `http://admin-ui.<tailnet-domain>/`
   - Scopes requested by the UI: `openid profile email`
   - Environment variables used by the service: `AUTH0_CLIENT_ID`, `AUTH0_CLIENT_SECRET`, `AUTH0_REDIRECT_URI`

4. **Optional: inject custom claims**
   - Add an Auth0 Action (or Rule) to push roles into tokens if needed (e.g., `https://yourdomain/roles`)
   - Set `AUTH0_ROLES_CLAIM` in broker/tool/agent if your claim key differs from the default

5. **Environment Variables by Service**

   - **Broker**
     - `AUTH0_DOMAIN`, `AUTH0_AUDIENCE`, optional `AUTH0_ROLES_CLAIM`
   - **Tool Service**
     - `AUTH0_DOMAIN`, `AUTH0_AUDIENCE`, `AUTH0_TOOL_SCOPE` (defaults to `tool.access:grant`)
   - **Agent**
     - `AUTH0_DOMAIN`, `AUTH0_AUDIENCE`, `AUTH0_CLIENT_ID`, `AUTH0_CLIENT_SECRET`, `AUTH0_SCOPES` (include grant scope)
      - `AGENT_GRANT_PERMISSIONS` (space-separated permission list such as `toolx:read toolx:write toolx:update`)
   - **Admin UI**
     - OIDC: `AUTH0_DOMAIN`, `AUTH0_CLIENT_ID`, `AUTH0_CLIENT_SECRET`, `AUTH0_REDIRECT_URI`
     - Backend: `AUTH0_AUDIENCE`, `AUTH0_M2M_CLIENT_ID`, `AUTH0_M2M_CLIENT_SECRET`, `AUTH0_SCOPES`
      - Session data: `SESSION_SECRET`
      - Permission list for grant flow: `AGENT_GRANT_PERMISSIONS`

Having this structure makes it easy to plug the right credentials into each Railway service (or other deployment environment).
