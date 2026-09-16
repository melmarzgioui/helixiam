# CLI & native-app authentication

Give a command-line tool, desktop app, or any other **native app** a first-class sign-in: a browser login (authorization code + PKCE), a headless device login (RFC 8628), and a **long-lived, silently-refreshed session** — no secret baked into the binary.

## What it is

A native app is a **public** OAuth client: it ships to end users, so it can't keep a client secret. Helix IAM authenticates it the way the major clouds do their CLIs (`az`, `gcloud`, `aws sso`):

| Flow | When to use | Grant |
| --- | --- | --- |
| **Browser** | The machine has a browser (a developer laptop) | `authorization_code` + PKCE, loopback redirect (RFC 8252) |
| **Device** | Headless — SSH sessions, CI shells, servers | `urn:ietf:params:oauth:grant-type:device_code` (RFC 8628) |
| **Service account** | Automation / CI with no human | `client_credentials` |

All three mint a normal Helix access token carrying the caller's identity (`sub`) and roles (`realm_access.roles` / `resource_access`), so your API authorizes them exactly like any other token.

!!! tip "Stay signed in for 30 days"
    Native-app clients may hold a **rotating refresh token**, so the CLI renews the access token silently in the background. Used within the refresh window (30 days by default) you stay signed in; leave it idle past the window and you simply sign in again. Rotation (a new refresh token on every renewal, the old one invalidated) keeps this OAuth 2.1-safe.

## The kubedna CLI (worked example)

The `kubedna` CLI is a native-app client. Its `login` command is **mode-aware**.

=== "Browser (default)"

    ```bash
    kubedna login
    ```

    Opens your browser to the realm's sign-in page, captures the redirect on a private loopback port, and stores a refreshable session. Add `--realm <realm>` to target a non-default realm.

    On a machine with no browser, print the URL instead of launching one:

    ```bash
    KUBEDNA_NO_BROWSER=1 kubedna login
    ```

=== "Device (headless)"

    ```bash
    kubedna login --device
    ```

    Prints a short code and a URL. Open the URL on any device, sign in, and approve the code; the CLI polls until it's approved.

=== "Service account (CI)"

    ```bash
    kubedna login --org acme \
      --client-id "$KUBEDNA_CLIENT_ID" \
      --client-secret "$KUBEDNA_CLIENT_SECRET"
    ```

    Authenticates as an OAuth client (no browser). Use this in pipelines.

Check and clear your session:

```bash
kubedna whoami     # who am I, which realm, token status
kubedna logout     # remove the stored session
```

The session is stored under `~/.kubedna/config.yaml` (override with `KUBEDNA_CONFIG`); the auth server is `KUBEDNA_IDP_URL`.

## Enable it for your own native app

The capability is not specific to the kubedna CLI — **any** public client you register can use it. Two steps:

1. **Register a public client** and mark it as a native app by enabling the **device grant** alongside `authorization_code` and `refresh_token`. In the console: [Applications](../manage/applications.md) → your app → **OIDC** → the client → enable `authorization_code`, `refresh_token`, and `Device code`. Register a **loopback redirect URI** (`http://127.0.0.1/callback`) for the browser flow. Leave it public (no secret) so PKCE is enforced.

2. **Set the refresh-token lifespan** you want (the idle window) on the client's **Advanced** tab — e.g. 30 days — and leave **reuse refresh tokens** off so tokens rotate.

That's it. Your app now gets browser + device login and a rotating, long-lived session, just like `kubedna`.

!!! note "Why this needs a native-app marker"
    By default Spring Authorization Server (which Helix is built on) — following the OAuth 2.1 browser-app guidance — does **not** issue refresh tokens to public clients on the authorization-code grant, because a refresh token in browser JavaScript is a risk. Helix relaxes this **only for native apps** (identified by the device grant, per RFC 8252), where a rotating refresh token is safe and expected. Browser SPAs keep the strict, no-refresh behaviour.

## How the flows work

### Browser (authorization code + PKCE + loopback)

```text
CLI                                   Helix realm                         Browser
 │  start loopback :<random>                                                  │
 │  open ─────────────────────────────────────────────────────────────────►  │
 │                     GET /realms/{realm}/oauth2/authorize?…code_challenge…   │
 │                                        sign in ◄───────────────────────────┤
 │  ◄──────────  302 http://127.0.0.1:<port>/callback?code=…&state=…          │
 │  POST /oauth2/token  (code + code_verifier, client_id, no secret)          │
 │  ◄──────────  access_token (+ refresh_token for native apps)               │
```

### Device (RFC 8628)

```text
CLI                                   Helix realm
 │  POST /oauth2/device_authorization  (client_id)                            │
 │  ◄──────────  device_code, user_code, verification_uri, verification_uri_complete
 │  show the user the code + URL                                              │
 │  POST /oauth2/token  (grant_type=device_code, device_code, client_id)  ──► │  authorization_pending…
 │  … user approves at /activate …                                           │
 │  ◄──────────  access_token (+ refresh_token)                               │
```

!!! warning "The device grant is OAuth2-only"
    The device flow does **not** support the `openid` scope (it issues access tokens, not ID tokens). Request API scopes such as `profile offline_access`; the access token still carries the user's `sub` and roles.

### Silent refresh

When the access token is near expiry the CLI renews it in the background:

```text
CLI                                   Helix realm
 │  POST /oauth2/token  (grant_type=refresh_token, refresh_token, client_id)   │
 │  ◄──────────  new access_token + NEW refresh_token (old one invalidated)    │
```

Each renewal issues a fresh refresh token and slides the idle window forward.

## Environment variables (kubedna CLI)

| Variable | Purpose |
| --- | --- |
| `KUBEDNA_IDP_URL` | Auth-server base URL (realm paths are appended) |
| `KUBEDNA_CONFIG` | Path to the CLI config (default `~/.kubedna/config.yaml`) |
| `KUBEDNA_NO_BROWSER` | Any value ⇒ print the sign-in URL instead of launching a browser |

## Related

- [OIDC quickstart](oidc-quickstart.md) — the underlying authorization-code + PKCE flow.
- [Workload identity](workload-identity.md) — keyless machine tokens for Kubernetes / CI.
- [Applications](../manage/applications.md) — register the client and its grants.
