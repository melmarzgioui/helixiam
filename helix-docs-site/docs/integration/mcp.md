# MCP authorization — protect an MCP server with Helix

The [Model Context Protocol](https://modelcontextprotocol.io) (MCP) lets an AI agent call *tools* on a server. The MCP **authorization** spec builds directly on OAuth 2.1: an MCP server is just an OAuth **resource server**, and the agent is an OAuth client. Helix is the **authorization server** — so any MCP client that follows the spec can discover Helix, get a token, and call your MCP server, with no Helix-specific code on either side.

This page shows the full handshake, the four RFCs that make it work, and a runnable end-to-end demo you can execute against a local Helix.

!!! tip "This is the agent story, applied to tools"
    An MCP server is just an API an agent calls, so everything in [Agent authorization](agent-authorization.md) applies unchanged: the token carries the caller's `nhi` identity and actor chain, its authority is the **intersection** of every bound, and it is **audience-bound** to the one MCP server it was minted for. MCP auth is the discovery + challenge protocol that gets that token into the agent's hands.

## The handshake

The whole point of the spec is that the agent needs **zero prior configuration** — it discovers everything from a `401`. Five steps:

```
  AGENT (MCP client)                 MCP SERVER (resource)              HELIX (authorization server)
        │                                   │                                   │
        │ 1. POST /mcp  (no token)          │                                   │
        │ ─────────────────────────────────▶                                   │
        │ 401 + WWW-Authenticate:           │                                   │
        │    Bearer resource_metadata="…"   │                                   │
        │ ◀─────────────────────────────────                                   │
        │                                   │                                   │
        │ 2. GET /.well-known/oauth-protected-resource   (RFC 9728)             │
        │ ─────────────────────────────────▶                                   │
        │    { resource, authorization_servers:[HELIX] }                        │
        │ ◀─────────────────────────────────                                   │
        │                                   │                                   │
        │ 3. GET /.well-known/openid-configuration        (RFC 8414)           │
        │ ─────────────────────────────────────────────────────────────────────▶
        │    { token_endpoint, … }                                              │
        │ ◀─────────────────────────────────────────────────────────────────────
        │                                   │                                   │
        │ 4. POST token_endpoint  grant_type=client_credentials                 │
        │        resource=<this MCP server>               (RFC 8707)           │
        │ ─────────────────────────────────────────────────────────────────────▶
        │    access_token  (aud = <this MCP server>, nhi=true, act chain)       │
        │ ◀─────────────────────────────────────────────────────────────────────
        │                                   │                                   │
        │ 5. POST /mcp   Authorization: Bearer <token>                          │
        │ ─────────────────────────────────▶                                   │
        │    200  tools/call result         │  (verifies signature, iss,        │
        │ ◀─────────────────────────────────    exp, and aud == this server)    │
```

| Step | Spec | What happens |
| --- | --- | --- |
| 1 | MCP auth / [RFC 9728](https://www.rfc-editor.org/rfc/rfc9728) | The unauthenticated call is refused with a `WWW-Authenticate: Bearer resource_metadata="…"` challenge pointing at the server's metadata. |
| 2 | [RFC 9728](https://www.rfc-editor.org/rfc/rfc9728) | The client fetches **Protected Resource Metadata**, learning the resource id and which authorization server (Helix) to use. |
| 3 | [RFC 8414](https://www.rfc-editor.org/rfc/rfc8414) | Standard OAuth/OIDC discovery on Helix yields the token endpoint (and, for interactive agents, the authorization + registration endpoints). |
| 4 | [RFC 8707](https://www.rfc-editor.org/rfc/rfc8707) | The client requests a token, passing `resource=<the MCP server>`. Helix **binds the token's `aud`** to exactly that server. |
| 5 | [RFC 9068](https://www.rfc-editor.org/rfc/rfc9068) | The server validates the JWT: signature via Helix's JWKS, issuer, expiry, and — critically — that `aud` is **this** server. |

## Why audience binding matters

Step 4 is the security crux. Because the token's `aud` is pinned to one MCP server (RFC 8707 resource indicators), a token minted for `payments-mcp` **cannot be replayed** against `email-mcp`, even though both trust the same Helix. A leaked or over-broad token can only ever hit the one resource it was scoped to. The demo below proves this with a negative test: a token bound to a *different* resource is rejected `401`.

!!! note "Machine tokens carry the realm issuer (RFC 9068)"
    Helix stamps every client-credentials access token with `iss` = the realm issuer it advertises in discovery — not the client id — so a standards-compliant MCP server validates it with no Helix-specific rules. Combined with the JWKS signature check and the `aud` binding, that is the complete trust anchor.

## In the console

The admin console has a dedicated **MCP authorization** screen (under **Integration**) that gathers everything on this page into one place for a realm. It's a read-only + generator surface — MCP callers are managed as ordinary [agents](agents.md), not here — with four parts:

- **Overview** — how many of your agents are MCP-capable, how many are active, and how many are expiring soon.
- **Authorization-server endpoints** — the realm's issuer, discovery, token, and Dynamic Client Registration URLs, each copyable, to paste into an MCP server or client.
- **MCP-capable agents** — the agents holding an `mcp` / `mcp:*` scope or role (the identities allowed to call MCP servers), with a link through to the Agents screen to manage them.
- **Protect your MCP server** — enter your MCP server's URL and it generates the exact RFC 9728 Protected Resource Metadata document, the `401` `WWW-Authenticate` challenge, and a DCR registration command for you to copy.

Use it as the starting point when wiring up a new MCP server; the sections below explain what each generated artifact means.

## Registering the agent's client

The agent authenticates to Helix as an OAuth client. Two ways to get one:

- **Pre-registered** — create a confidential client (or a [service account](agents.md)) in the console and hand the agent its `client_id`/`client_secret`. Bind it to an [Agent](agents.md) so its tokens carry the `nhi.*` identity and its least-privilege roles.
- **Dynamic Client Registration** ([RFC 7591](https://www.rfc-editor.org/rfc/rfc7591)) — for agents that self-onboard, Helix exposes `POST /connect/register`. The agent registers itself, then runs the handshake above. Governance still applies: DCR clients appear in the console and can be reviewed, expired, and revoked like any other.

## Runnable demo

A zero-dependency demo lives in [`helix-mcp-demo/`](https://github.com/kubedna) next to the auth server. It contains a minimal MCP resource server, an MCP client, and the two tests, all in plain Node (no npm install).

```bash
cd platform/microservices/authorization/helix-mcp-demo
./run-demo.sh          # seeds a demo agent+client, starts the server, runs the handshake + negative test
```

What each file does:

| File | Role |
| --- | --- |
| `mcp-server.js` | The MCP **resource server** — publishes RFC 9728 metadata, issues the `401` challenge, and verifies tokens (signature, `iss`, `exp`, `aud`). |
| `mcp-client.js` | The **agent** — runs all five handshake steps and prints each one. |
| `test-aud-binding.js` | Negative test — proves a token bound to a *different* resource is rejected. |
| `setup.sql` | Seeds the demo agent (`mcp-demo-agent`) and its bound client. |

A successful run ends with the tool call returning the caller's non-human identity:

```json
{
  "ok": true,
  "result": "Hello from the Helix-protected MCP server 👋",
  "caller": {
    "nhi": true,
    "agent_name": "mcp-demo-agent",
    "agent_owner": "alice@acme.example",
    "audience": "http://localhost:9800",
    "realm_roles": ["mcp:tools"]
  }
}
```

## Building your own MCP server

The server side is small. To Helix-protect any MCP (or plain HTTP) server:

1. **Publish** `GET /.well-known/oauth-protected-resource` returning at least `resource` (your server's URL) and `authorization_servers` (your Helix realm issuer). See RFC 9728 for the full field set.
2. **Challenge** unauthenticated calls with `401` and `WWW-Authenticate: Bearer resource_metadata="<that URL>"`.
3. **Verify** each bearer token: fetch Helix's JWKS (from discovery), check the RS256 signature, then assert `iss` = your realm issuer, `exp` is in the future, and `aud` contains your server's URL. Optionally require a scope.

`mcp-server.js` is ~120 lines of exactly this and is a fine starting point. Everything else — who the agent is, what it may do, how long the token lives, how to revoke it — is the standard Helix [agent model](agent-authorization.md).
