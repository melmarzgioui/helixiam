# Admin console login (`helix-console` client)

The Helix admin console signs in through a standard OpenID Connect client — **`helix-console`** —
using the authorization code flow with PKCE, exactly like any other application you register. This
means an admin's console login is a real **single sign-on session**: it appears on the **Sessions**
screen and can be ended with Single Logout, the same as Keycloak's `security-admin-console`.

## How it works

1. Opening the console with no session redirects the browser to
   `/realms/{realm}/oauth2/authorize?client_id=helix-console&…` (authorization code + PKCE).
2. You sign in on the normal login page (the same page as before — it is shown *inside* the
   authorize redirect, so you still enter your password once).
3. The console completes the token exchange at `/realms/{realm}/oauth2/token`. That exchange is what
   registers the SSO session (the OIDC `sid`), so the login now shows on the Sessions screen.
4. Admin API calls (`/admin/**`) continue to use the session cookie established during login — the
   token exchange only registers the session; it does not change how the admin API is authorized.

Sign-out performs RP-initiated logout (`/realms/{realm}/connect/logout`) so both the cookie session
and the SSO session end together.

## Seeding & configuration

`helix-console` is **seeded automatically in every realm** at startup and whenever a realm is
created — no manual registration. It is a public client (no secret, PKCE required) with scopes
`openid profile`.

Its redirect URI, web origin, and post-logout URI are derived from a single setting:

| Setting | Env var | Default |
| --- | --- | --- |
| Console base URL | `HELIX_CONSOLE_BASE_URL` | `http://localhost:8180` |

Point this at the console's external base URL (scheme + host + port). On every startup the client's
`redirect_uri` (`{base}/console/callback`), web origin (`{base}`), and post-logout URI (`{base}/`)
are reconciled from it, so **changing the deployment URL and restarting is all that's needed** — no
manual client edit.

## Recovery (break-glass)

The console client is protected: it **self-heals** (recreated on the next restart if deleted) and
the admin API **refuses to delete it**. If the client is ever misconfigured (for example a wrong
`HELIX_CONSOLE_BASE_URL`), an admin can still sign in directly at the IdP login page —
`/realms/{realm}/login` — to get a session and fix the configuration. This break-glass path is always
available.

## In the console

Because `helix-console` is a real OIDC client, it appears wherever clients do:

- Under **Manage → Applications & clients → OIDC/SAML clients** it shows as **Helix Admin Console**, a public client (PKCE) with scopes `openid profile`. You can inspect it, but the admin API and self-heal keep it from being deleted or renamed away.
- Under **Manage → Users & access → Sessions**, an admin's console login shows as an active SSO session that can be ended with Single Logout — see [Sessions](sessions.md).

## Over the API

`helix-console` is listed and read like any other client under `/admin/realms/{realm}/clients`. The examples below assume you have set `$HELIX_URL` / `$REALM` and logged in — see [Authenticating to the API](../getting-started/api-authentication.md).

```bash
# It surfaces in the normal clients list
curl -s -b cookies.txt "$HELIX_URL/admin/realms/$REALM/clients"
```
```json
[
  { "clientId": "helix-console", "name": "Helix Admin Console", "publicClient": true, "grantTypes": ["authorization_code","refresh_token"] }
]
```

!!! warning "Protected client"
    A `DELETE` against the `helix-console` client is refused, and if it is ever removed out-of-band it is recreated on the next restart. Do not manage its `redirect_uri` / web origin by hand — they are reconciled from `HELIX_CONSOLE_BASE_URL` on every startup.

## See also

- [OIDC clients](oidc-clients.md)
- [Sessions](sessions.md)
- [Console authentication & setup](../getting-started/configuration.md)
- [Authenticating to the API](../getting-started/api-authentication.md)
