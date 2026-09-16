# Realm settings

Tune each realm's session behaviour, branding, languages and token audiences from a single tabbed configuration page.

## What it is

A realm is a fully isolated tenant in Helix IAM — its own users, clients, keys and policy. The **Realm settings** screen is where you shape how that tenant behaves at runtime. Settings are scoped to the realm: changing one realm never affects another.

The page is organised into tabs:

- **Sessions** — single sign-on session policy: idle timeout, maximum session lifetime, and whether *remember-me* is offered on the login page.
- **Login & branding** — the human-facing identity of the realm's sign-in pages (see [Login theming](theming.md) for the full white-label workflow).
- **Registration** — whether this realm accepts self-service sign-ups, and what the closed state looks like.
- **Internationalization** — the locales offered to end users, so login, email and account pages render in the right language.
- **Resource Indicators** — an audience allow-list (RFC 8707) that constrains which `resource` values clients may request in a token, keeping access tokens narrowly scoped.

## In the console

1. Open **Manage → Realms → Realm settings**.
2. Pick a tab and edit the fields.
3. **Save** — changes apply to new sessions and token requests immediately.

### Sessions

| Field | Effect |
| --- | --- |
| Idle timeout | A session ends after this period of inactivity. |
| Max session lifetime | Hard cap on a session's age regardless of activity. |
| Remember me | Lets returning users keep a longer-lived session from the login page. |

These policies are enforced across every application in the realm and underpin silent SSO and re-authentication prompts.

### Registration

| Field | Effect |
| --- | --- |
| Allow self-registration | Lets people create their own account for this realm at `/register`. |

Self-registration only runs when **both** switches agree: the platform-wide `USER_REGISTRATION_ENABLED` environment variable ([Configuration](../getting-started/configuration.md)) and this realm's **Allow self-registration** toggle. If either one is off, the realm's `/register` page shows a "registration closed" panel and no sign-up is accepted.

When it's on, `/register` uses the same per-realm [login branding](theming.md) as the sign-in page — logo, colours, welcome text and custom CSS. The fields on the sign-up form, and which of them are required, are not set here: they come from the realm's claim catalogue. See [Self-registration fields](../manage/scopes-and-claims.md#self-registration-fields).

### Internationalization

Enable the locales your tenant serves. End users get login, [notification](notifications.md) and account-console content in their preferred language; unsupported locales fall back to the realm default.

### Resource Indicators (RFC 8707)

Add the audiences clients are permitted to request. When a client asks for a `resource` that is not on the allow-list, the request is rejected with `invalid_target` — so a token minted for one API can't be replayed against another.

## Over the API

All four tab groups are one `RealmSettingsDto` resource under `/admin/realms/{realm}/settings`. The examples below assume you have set `$HELIX_URL` / `$REALM` and logged in — see [Authenticating to the API](../getting-started/api-authentication.md).

### Read the settings

The response carries the full realm configuration — session policy, password rules, lockout, CAPTCHA, adaptive-risk thresholds and branding — in one object (abridged here):

```bash
curl -s -b cookies.txt "$HELIX_URL/admin/realms/$REALM/settings"
```
```json
{
  "realmId": "acme",
  "displayName": "Acme",
  "issuer": null,
  "accessTokenTtlSeconds": 3600,
  "refreshTokenTtlSeconds": 5184000,
  "reuseRefreshTokens": false,
  "requireMfa": false,
  "ssoSessionIdleTimeoutSeconds": 1800,
  "ssoSessionMaxLifetimeSeconds": 36000,
  "rememberMe": false,
  "rememberMeLifetimeSeconds": 2592000,
  "lockoutEnabled": false,
  "maxLoginFailures": 5,
  "lockoutDurationSeconds": 900,
  "passwordMinLength": 12,
  "breachedPasswordCheck": false,
  "captchaProvider": "none",
  "maxConcurrentSessions": 0,
  "riskPolicyEnabled": false,
  "riskMediumThreshold": 40,
  "riskHighThreshold": 70,
  "logoUrl": null,
  "primaryColor": null,
  "backgroundColor": null,
  "welcomeText": null,
  "customCss": null,
  "registrationEnabled": true
}
```

### Update the settings

Submit the full settings object (a `PUT` replaces it). Refresh CSRF after the read:

```bash
# Refresh CSRF after any GET, then PUT (see the auth guide for the helper)
curl -s -b cookies.txt -c cookies.txt "$HELIX_URL/admin/realms/$REALM/settings" >/dev/null
CSRF=$(awk '$6=="XSRF-TOKEN"{t=$7} END{print t}' cookies.txt)

curl -s -b cookies.txt -X PUT \
  -H "Content-Type: application/json" \
  -H "X-XSRF-TOKEN: $CSRF" \
  -d '{
        "displayName": "Acme",
        "ssoSessionIdleTimeoutSeconds": 900,
        "rememberMe": true,
        "lockoutEnabled": true,
        "maxLoginFailures": 10,
        "breachedPasswordCheck": true,
        "registrationEnabled": true
      }' \
  "$HELIX_URL/admin/realms/$REALM/settings"
```

The response echoes the updated `RealmSettingsDto`.

!!! note "Resource Indicators live at the realm level too"
    The RFC 8707 audience allow-list is edited on the **Resource Indicators** tab and enforced on token requests. See [Resource Indicators (RFC 8707)](#resource-indicators-rfc-8707) above.

### Full endpoint set

| Method & path (under `/admin/realms/{realm}`) | Purpose |
| --- | --- |
| `GET /settings` · `PUT /settings` | Read / replace the full realm settings object |

## See also

- [Login theming](theming.md)
- [Client scopes & claims](../manage/scopes-and-claims.md) — the self-registration form's fields
- [Notifications](notifications.md)
- [Realm keys](realm-keys.md)
- [Configuration](../getting-started/configuration.md)
