# Agent authorization — roles, least privilege & scenarios

How much can a non-human identity *do*? Getting this right is the single most important security decision for AI agents and automations. Helix uses one rule everywhere, and it is deliberately **not** "the agent gets its owner's permissions."

!!! danger "An agent is **not** its owner"
    The **owner** of an [agent](agents.md) answers *"who is accountable — who do I audit and revoke?"* It is **not** a source of permissions. Copying an owner's roles onto their bot is the classic non-human-identity mistake: a small invoice bot ends up with a senior engineer's entire access, so a leaked secret or a prompt-injection gives an attacker *everything the owner could do*. Owners get promoted, change teams, and leave — and a bot that copied their roles silently drifts out of policy. **Owner = accountability. Roles = least privilege, granted to the agent itself.**

## The one rule

> **A token's effective permissions are the _intersection_ of every bound that applies — never a union.**

Authority can only ever **shrink**. Four bounds stack:

```
  EFFECTIVE PERMISSIONS = ∩ of every applicable bound        (monotonic — only shrinks)

   ┌─ 1. AGENT GRANT ───────────────────┐  the agent's OWN least-privilege roles
   │      invoices:read                  │  (its standing authority — what it can do alone)
   │   ┌─ 2. DELEGATED SUBJECT ───────┐  │  ONLY when acting FOR a user: that user's roles
   │   │      bob → invoices:*         │  │  (absent when autonomous ⇒ runs on bound 1 alone)
   │   │   ┌─ 3. REQUEST SCOPE ──────┐ │  │  this specific call: target resource + scopes
   │   │   │   aud = invoice-api      │ │  │  (RFC 8707 — a token for one API can't hit another)
   │   │   │   scope = invoices:read  │ │  │
   │   │   └─────────────────────────┘ │  │
   │   └──────────────────────────────┘  │
   └─────────────────────────────────────┘
            ∩  4. CEILING (owner roles / org policy)  ← a maximum CAP, never a grant
   ───────────────────────────────────────────────────────
        =  exactly what this token may do, for this one call
```

Four controls wrap all of it: **short token lifetimes · expiry · the lifecycle kill-switch · chain attenuation** (each agent→sub-agent hop re-intersects, so a tool an agent calls can never out-scope the agent) — and every token is fully **audited** (the `nhi` marker plus the actor chain).

## Where each bound comes from

| Bound | What it is | How you set it |
| --- | --- | --- |
| **1. Agent grant** | the agent's own least-privilege roles — its standing authority | per-agent **Roles** on the Agents screen, and/or the **service-account roles** of its [bound client](agents.md) |
| **2. Delegated subject** | the *acting user's* roles, when the agent acts **on behalf of** someone | established at delegation time (`act` claim) — never the owner's roles |
| **3. Request scope** | this call's target resource + requested scopes | [resource indicators](import-export.md) (RFC 8707) + the scopes requested |
| **4. Ceiling** | a maximum the agent may never exceed | owner's roles and/or org policy, applied as a cap |

## Scenarios — how the rule covers everything

| Scenario | Bounds in play | What the agent ends up with |
| --- | --- | --- |
| **Autonomous bot** — a cron job, no human present | 1 ∩ 4 | its own least-privilege roles, capped by policy |
| **Acts for a user** — a copilot doing something *as* Bob | 1 ∩ 2 ∩ 3 ∩ 4 | **Bob's** rights, narrowed to the agent's leash and this one call |
| **Shared multi-user agent** — one support copilot, many users | same, the user differs each request | each token is scoped to the **one** user it serves right now — never a union of all of them |
| **Agent → sub-agent chain** — tool calls, MCP servers | re-intersect at every hop | authority strictly shrinks down the chain; a tool can't out-scope its caller |
| **Per-tool / per-API call** | bound 3 narrows | an audience-bound token — it can't be replayed against a different API |
| **One-off / ephemeral task** | + expiry / short TTL | the authority evaporates on its own |
| **Just-in-time elevation** — normally read-only, needs write for one approved task | temporarily widen bound 1 (approval-gated) | bounded, time-limited elevation — never standing |
| **Compromise, leak, or offboarding** | the lifecycle gate | **suspend or revoke → tokens stop at the next mint**, instantly |

## What a token looks like

An agent token carries its authorization (roles/scopes) **and** its identity (`nhi` + who/owner/purpose) together, so a resource server can both enforce *and* attribute:

```json
{
  "sub": "billing-bot-client",
  "nhi": true,
  "agent_id": "9f1c…",
  "agent_owner": "alice@acme.example",
  "agent_purpose": "reconciles invoices nightly",
  "realm_access": { "roles": ["invoices:read"] },
  "scope": "openid invoices:read"
}
```

A resource server should branch on `nhi`: apply tighter rate limits, require human-in-the-loop for sensitive actions, and log **which** agent and **whose** authority acted.

## Practical guidance

- **Give every agent its own bound client** (1 agent ↔ 1 client). Then the agent's grant is unambiguous and revoking it never affects another bot.
- **Start from zero.** Grant only the roles the task needs. Add, never copy.
- **Never reuse a human's account or roles for a bot.** If a bot needs to act *as* a person, use delegation (bound 2) — the person's rights, intersected down — not a copy of their roles.
- **Keep token lifetimes short** and set an **expiry** on time-boxed agents — the kill-switch stops *new* tokens, but already-issued ones live out their TTL.
- **Review regularly.** Owners change; grants accumulate. Periodically re-check what each agent can do.

## See also

- [Agents (AI / non-human identity)](agents.md) — register, bind, and run the lifecycle
- [Import / export & migration](import-export.md) — ship agents and their roles as code
- [Workload Identity](workload-identity.md) — keyless federated credentials an agent can authenticate with
