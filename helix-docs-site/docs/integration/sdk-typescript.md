# TypeScript SDK

Add Helix login to any web or Node app, and drive the admin API from code, with one typed package.

## What it is

`@helix-iam/sdk` is the official TypeScript SDK. It ships two surfaces:

- **OIDC relying-party helpers** — everything you need to log a user in: discovery, PKCE, the authorize URL, the code exchange, refresh, userinfo, and logout.
- **A typed admin client** — manage applications, users, and roles over the admin API, authenticated with OAuth2 client credentials and automatic token caching.

It runs in **Node 18+** and modern **browsers** (the OIDC helpers use the Web Crypto API for PKCE).

```bash
npm install @helix-iam/sdk
```

## OIDC helpers

| Helper | Purpose |
| --- | --- |
| `realmIssuer(host, realm)` | Build the realm issuer URL |
| `generatePkcePair()` | Create an `S256` verifier + challenge |
| `buildAuthorizationUrl(opts)` | Compose the `/oauth2/authorize` URL |
| `parseCallbackParams(url)` | Read `code` / `state` from the redirect |
| `exchangeCode(opts)` | Swap the code for tokens at `/oauth2/token` |
| `refresh(opts)` | Refresh an access token |
| `userinfo(token)` | Fetch the user's claims |
| `buildEndSessionUrl(opts)` | Compose the RP-initiated logout URL |

## Quickstart (5 minutes)

```ts
import {
  realmIssuer, generatePkcePair, buildAuthorizationUrl,
  parseCallbackParams, exchangeCode, userinfo,
} from "@helix-iam/sdk";

const issuer = realmIssuer("https://auth.example.com", "acme");
const redirectUri = "https://app.example.com/callback";

// 1. Start login
const { verifier, challenge } = await generatePkcePair();
const url = buildAuthorizationUrl({
  issuer,
  clientId: "acme-web",
  redirectUri,
  scope: "openid profile email",
  codeChallenge: challenge,
});
// store `verifier` (e.g. in session), then redirect the browser to `url`

// 2. Handle the callback
const { code } = parseCallbackParams(window.location.href);
const tokens = await exchangeCode({
  issuer, clientId: "acme-web", redirectUri, code, codeVerifier: verifier,
});

// 3. Read the user
const me = await userinfo(tokens.accessToken);
```

Confidential clients pass `clientSecret` to `exchangeCode` instead of relying on PKCE alone.

## Express adapter

For server-side apps, the bundled Express adapter wires the login route, callback, session, and logout in a few lines:

```ts
import express from "express";
import { helixAuth } from "@helix-iam/sdk/express";

const app = express();
app.use(helixAuth({
  issuer: "https://auth.example.com/realms/acme",
  clientId: "acme-web",
  clientSecret: process.env.HELIX_CLIENT_SECRET,
  redirectUri: "https://app.example.com/callback",
}));

app.get("/profile", (req, res) => res.json(req.user)); // populated after login
```

## Admin client

```ts
import { createAdminClient } from "@helix-iam/sdk";

const admin = createAdminClient({
  issuer: "https://auth.example.com/realms/acme",
  clientId: "automation",
  clientSecret: process.env.HELIX_CLIENT_SECRET,
});

const users = await admin.users.list({ search: "jane" });
await admin.roles.assign(users[0].id, "billing-admin");
```

!!! note "Token caching"
    The admin client fetches a client-credentials token on first use and refreshes it transparently before expiry — you never manage tokens by hand.

## See also

- [OIDC quickstart](oidc-quickstart.md)
- [Mobile SDK](sdk-mobile.md)
- [Terraform provider](terraform.md)
- [API reference](api-reference.md)
