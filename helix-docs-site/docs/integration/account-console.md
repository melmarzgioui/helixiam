# Account Console

Give every user a self-service home for their profile, credentials, sessions, and privacy — no support ticket required.

## What it is

The Account Console is the end-user self-service app that ships with each realm. Signed-in users manage their own identity end to end: profile details, credentials, active sessions, the apps they have consented to, linked external logins, and their personal data under GDPR.

It lives under the realm at:

```
/realms/{realm}/account
```

Behind the app is a self-service **API** under `/realms/{realm}/account/**`. Unlike the [admin API](../getting-started/api-authentication.md) (session + CSRF), it is authenticated by the **user's own OAuth2 bearer token** — each user only ever sees and edits their own data.

## What users can do

| Area | Endpoint (under `/realms/{realm}/account`) | What it covers |
| --- | --- | --- |
| Profile | `GET · PUT /profile` | Name, email, and other profile attributes |
| Password | `PUT /password` | Change the account password |
| Credentials | `GET /credentials` · `DELETE /credentials/{type}/{id}` | Passwords, OTP, passkeys, and enrolled devices |
| Sessions | `GET /sessions` · `DELETE /sessions/{ssoSessionId}` | View active sessions and sign out remote ones |
| Consents | `GET /consents` · `DELETE /consents/{clientId}` | Review and revoke app consents |
| Identities | `GET /identities` · `DELETE /identities/{alias}` | Linked external / social logins |
| GDPR | `GET /gdpr/export` · `GET /gdpr/consents` · `DELETE /gdpr/consents/{clientId}` | Export personal data and manage consent records |

## In the console

Review the self-service surface under **Integration → Account console**. End users reach it directly at `/realms/{realm}/account` after signing in.

1. Ensure users can sign in — the Account Console uses the realm's normal [authentication](../authentication/index.md) flow.
2. Point users at `/realms/{realm}/account`; the app inherits the realm's login theming.
3. To drive it programmatically, obtain a user bearer token via an [OIDC login](oidc-quickstart.md) and call the `/account/**` API directly.

## Over the API

Every call carries the signed-in user's bearer token — no cookie jar, no CSRF header. A request without a valid token is rejected with `401 Unauthorized`.

### Read the signed-in user's profile

```bash
curl -s "$HELIX_URL/realms/$REALM/account/profile" \
  -H "Authorization: Bearer $USER_TOKEN"
```
```json
{
  "realmId": "acme",
  "userId": "684db0eb-4afe-44f9-ad16-37a64f3496ea",
  "username": "jane",
  "email": "jane@example.com",
  "enabled": true,
  "locked": false,
  "mfaEnabled": false,
  "roles": ["user"],
  "attributes": {},
  "createdAt": 1783339573376
}
```

The profile endpoint returns the same `UserAdminDto` shape as the admin users API, but scoped to the caller's own account. Use `GET /account/sessions` to list active sessions, `GET /account/credentials` to enumerate factors, and the matching `DELETE` calls to sign out a device or revoke a credential.

!!! tip "Branded to match your realm"
    The Account Console inherits the realm's login theming, so it feels like part of your product, not a bolt-on.

## Highlights

### Self-service credentials

Users add and remove their own factors — set up a passkey, enrol an OTP authenticator, register a device, or change their password — without admin involvement. This pairs directly with the realm's [authentication](../authentication/index.md) configuration.

### Session control

Users see every active session and can sign out any device they no longer recognise — a simple, effective response to "I left myself logged in on a shared computer."

### Privacy and consent

Consents lists the apps a user has authorized, with one-click revoke. The GDPR area lets users export their own data, helping you meet data-subject requests with no manual effort.

## See also

- [Authentication overview](../authentication/index.md)
- [Passkeys](../authentication/passkeys.md)
- [Sessions admin](../manage/sessions.md)
- [Users](../manage/users.md)
- [API reference](api-reference.md)
