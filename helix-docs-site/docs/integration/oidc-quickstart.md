# OIDC Quickstart

Log a user in with standards-based OpenID Connect — authorization code + PKCE — in a few HTTP calls.

## What it is

Every realm in Helix IAM is its own OpenID Connect issuer at `https://<host>/realms/<realm>`. Point any compliant OIDC client at the realm's discovery document and you get login, single sign-on, token issuance, and logout out of the box.

```bash
curl https://auth.example.com/realms/acme/.well-known/openid-configuration
```

The discovery document advertises every endpoint you need under the realm:

| Endpoint | Purpose |
| --- | --- |
| `/oauth2/authorize` | Start the login (authorization) request |
| `/oauth2/token` | Exchange the code, refresh tokens |
| `/userinfo` | Read the signed-in user's claims |
| `/oauth2/jwks` | Public keys to verify token signatures |
| `/connect/logout` | RP-initiated single logout |

## Before you start

[Register an application](../manage/applications.md) and add an OIDC client to it. Note the `client_id`, the allowed **redirect URI**, and — for a confidential client — the **client secret**.

!!! tip "Public vs confidential clients"
    Browser SPAs and mobile apps are **public** clients: they cannot keep a secret, so they protect the code exchange with **PKCE**. Server-side apps are **confidential** clients and authenticate with a **client secret** (PKCE is still recommended).

## Quickstart

### 1. Build the authorize URL

Generate a PKCE verifier and its `S256` challenge, then redirect the user's browser to:

```http
GET /realms/acme/oauth2/authorize
  ?response_type=code
  &client_id=acme-web
  &redirect_uri=https://app.example.com/callback
  &scope=openid profile email
  &state=ehV9...random
  &code_challenge=YS3v...base64url
  &code_challenge_method=S256
```

After the user authenticates, Helix redirects back to your `redirect_uri` with `?code=...&state=...`. Verify `state` matches the value you sent.

### 2. Exchange the code for tokens

```bash
curl -X POST https://auth.example.com/realms/acme/oauth2/token \
  -d grant_type=authorization_code \
  -d client_id=acme-web \
  -d code=$AUTH_CODE \
  -d redirect_uri=https://app.example.com/callback \
  -d code_verifier=$PKCE_VERIFIER
```

A confidential client adds `-d client_secret=$SECRET` (or HTTP Basic auth) instead of, or alongside, the verifier. You receive an `access_token`, an `id_token`, and a `refresh_token`.

### 3. Read the user's claims

```bash
curl https://auth.example.com/realms/acme/userinfo \
  -H "Authorization: Bearer $ACCESS_TOKEN"
```

### 4. Refresh the access token

```bash
curl -X POST https://auth.example.com/realms/acme/oauth2/token \
  -d grant_type=refresh_token \
  -d client_id=acme-web \
  -d refresh_token=$REFRESH_TOKEN
```

### 5. Log the user out (RP-initiated)

```http
GET /realms/acme/connect/logout
  ?id_token_hint=$ID_TOKEN
  &post_logout_redirect_uri=https://app.example.com/
```

## Verify tokens

Always validate the `id_token` signature against the realm's `/oauth2/jwks`, and check `iss` equals the realm issuer, `aud` contains your `client_id`, and the token has not expired. The [TypeScript SDK](sdk-typescript.md) handles discovery, PKCE, and token verification for you.

## See also

- [Register an application](../manage/applications.md)
- [TypeScript SDK](sdk-typescript.md)
- [Mobile SDK](sdk-mobile.md)
- [API reference](api-reference.md)
