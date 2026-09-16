# Agents (AI / non-human identity)

Give every AI agent, bot, and automation a **first-class identity** — with an accountable human owner, a lifecycle you control, and tokens that say *what* is calling and *on whose authority*. Agents build on the same OAuth/OIDC engine as your apps, so a resource server treats an agent token like any other — but can tell a non-human caller apart and trace it to its owner.

## Why an agent is more than a client

A plain OAuth client is anonymous machinery. An **agent** is a *principal*:

| | OAuth client | Helix agent |
| --- | --- | --- |
| Accountable **owner** | — | a named human (revocation target, audit trail) |
| **Purpose** | — | recorded, surfaced on every token |
| **Lifecycle** | enabled/disabled | ACTIVE → SUSPENDED → REVOKED, with optional expiry |
| **Kill-switch** | delete the client | suspend/revoke — tokens stop **immediately**, no client teardown |
| Token marking | indistinguishable from a user | `nhi: true` + agent id / owner / purpose claims |

An agent is bound to an OIDC client for issuance (like a workload-identity credential), so it can authenticate by `client_credentials`, `private_key_jwt`, or a federated workload JWT — see [Workload Identity](workload-identity.md).

## Register an agent

In the console: **Integration → Agents → Register agent**. Or over the admin API:

```bash
curl -X POST https://auth.example.com/admin/realms/acme/agents \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d '{
        "name": "billing-bot",
        "displayName": "Billing reconciliation bot",
        "description": "reconciles invoices nightly",
        "owner": "alice@acme.example",
        "authMethod": "SECRET",
        "clientId": "billing-bot-client",
        "scopes": "openid invoices:read",
        "expiresAt": 1767225600000
      }'
```

`name` is the realm-unique natural key. `owner` is required — every agent has an accountable human.

## The tokens an agent gets

When an agent authenticates (e.g. `client_credentials` on its bound client), its access token carries a non-human-identity marker plus its identity, alongside the normal scopes/roles:

```json
{
  "sub": "billing-bot-client",
  "nhi": true,
  "agent_id": "9f1c…",
  "agent_name": "billing-bot",
  "agent_owner": "alice@acme.example",
  "agent_purpose": "reconciles invoices nightly",
  "scope": "openid invoices:read"
}
```

A resource server can branch on `nhi` (apply stricter rate limits, require human-in-the-loop for sensitive actions) and log **which** agent and **whose** authority acted.

## Lifecycle is the kill-switch

Lifecycle is enforced **at the moment of issuance**, not just at the admin layer:

| Action | Effect |
| --- | --- |
| **Suspend** | status → `SUSPENDED`; the next token request is **denied** (`invalid_client`). Re-**activate** to restore. |
| **Revoke** | status → `REVOKED`; permanently denied. |
| **Expiry** | once `expiresAt` passes the agent is treated as expired and denied. |

Because the gate runs on every `client_credentials` issuance, suspending or revoking an agent **stops it minting new tokens right away** — you don't have to tear down its client or rotate secrets. (Already-issued access tokens live out their short TTL; keep agent token lifetimes short.)

!!! note "Gate scope"
    The lifecycle gate runs only for machine (`client_credentials`) issuance and is best-effort on the registry — a registry hiccup never blocks an ordinary client's tokens; only a positively-resolved, non-active agent is denied.

## Govern your fleet

**Integration → Agents** is a governance surface, not just a list. At the top, a rollup counts the whole
realm's non-human identities — **registered, active, suspended, revoked,** and **expiring soon** (any active
agent whose `expiresAt` is within the next 14 days — your rotation worklist).

Open an agent to see its full identity in one place:

- the **accountable owner** and purpose;
- its **capabilities** — the least-privilege scopes and roles *its own* tokens carry (never the owner's full access);
- the **`nhi.*` markers** every token it mints is stamped with (`nhi`, `agent_id`, `agent_name`, `agent_owner`, `agent_purpose`), so a resource server can tell a bot from a human and trace it to its owner;
- a prominent **kill-switch** — Suspend or Revoke takes effect on the agent's next token request.

### Owner integrity — no orphaned identities

An agent's `owner` is required at creation, but a *populated* owner isn't the same as a *live, accountable*
one. Two dangerous states creep in over time — a **fictional** owner (the string matches no user in the
realm) and, far more common, an **orphaned** or "zombie" owner (the person was real, then left the company
and was deprovisioned). Either way nobody is actually accountable, yet the agent keeps minting tokens.

Helix closes this on two fronts:

- **Owner review.** The rollup adds an **Owner issues** count, and an **Owner review** panel lists every
  agent whose owner isn't a live realm user — tagged **Unknown owner** or **Orphaned** — with one-click
  **Reassign owner** or **Suspend**. Each agent also carries an owner-status badge in its detail drawer.
- **Deprovisioning cascade.** When a human is disabled or deleted, Helix automatically **suspends the
  agents they own** (audited), so a departing person never leaves live, unattended non-human identities
  behind. Only the departed owner's still-active agents are touched; everything else is left alone.

Together these make ownership *true over time*, not just true at creation.

## Agents as code

Agents are part of [realm config-as-code](import-export.md) — they appear as the `agents` slice in a realm export and import idempotently by name, so you ship an agent roster alongside your deployment:

```json
{
  "formatVersion": 2,
  "agents": [
    { "name": "billing-bot", "owner": "alice@acme.example", "authMethod": "SECRET",
      "clientId": "billing-bot-client", "scopes": "openid invoices:read", "status": "ACTIVE" }
  ]
}
```

No secret crosses the wire — an agent authenticates through its bound client / workload credential, established per environment.

## Acting on behalf of a user (delegation)

An agent can act **for** a specific user — a copilot doing something *as* the person who asked. It presents the user's token as `subject_token` and its own token as `actor_token` to the delegation exchange (RFC 8693):

```bash
curl -X POST https://auth.example.com/realms/acme/agent/delegation/token \
  -d grant_type=urn:ietf:params:oauth:grant-type:token-exchange \
  -d subject_token=$USER_ACCESS_TOKEN \
  -d actor_token=$AGENT_ACCESS_TOKEN \
  -d scope='invoices:read'
```

Both tokens are verified against the realm key, the agent must still be **ACTIVE**, and the minted token carries `sub`=the user, an `act` claim naming the agent, and roles that are the **intersection** of the user's roles, the agent's own leash, and the requested scope — never a union, never the owner's:

```json
{
  "sub": "alice",                                  // acting FOR the user
  "act": { "sub": "billing-bot-client" },          // WHAT acted (nested for agent→sub-agent chains)
  "nhi": true,
  "realm_access": { "roles": ["invoices:read"] }   // ⊆ (alice's roles ∩ the agent's leash)
}
```

See the full model and every scenario in **[Agent authorization & scenarios](agent-authorization.md)**.

## See also

- [Agent authorization & scenarios](agent-authorization.md) — the roles / least-privilege / intersection model
- [MCP authorization](mcp.md) — let an agent call a Model Context Protocol tool server (OAuth 2.1 + RFC 9728)
- [Workload Identity (Kubernetes/CI)](workload-identity.md) — keyless federated tokens an agent can authenticate with
- [Import / export & migration](import-export.md) — ship agents as code
- [Resource Indicators](import-export.md) — narrow an agent token's audience to one resource server
