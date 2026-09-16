# Login theming

White-label every realm's sign-in experience so it looks like it belongs to the tenant, not the platform.

## What it is

Each realm carries its own **login branding**: a logo, a colour scheme and related presentation fields. When a user lands on a realm's sign-in pages they see the tenant's identity — the right logo, the right colours — with no generic platform chrome. One Helix IAM deployment can therefore serve many tenants, each with a fully branded login.

Branding is scoped to the realm and applies across its authentication surfaces: the login form, multi-factor challenges, password and account flows, and — where [self-registration](realm-settings.md#registration) is enabled — the `/register` sign-up page.

## In the console

1. Open **Manage → Realms → Login theming** (the **Login & branding** tab of the realm's settings).
2. Upload the tenant **logo**.
3. Set the brand **colours** and the remaining branding fields.
4. **Save** and reload a sign-in page to confirm the result.

Because branding is part of [realm settings](realm-settings.md), it is versioned and managed exactly like the realm's other configuration.

!!! tip "Match the locale too"
    Pair branding with the realm's [internationalization](realm-settings.md) settings so a tenant's users get both the right look and the right language on the login page.

## How to white-label a tenant

- Use a logo that reads well on the realm's background colour.
- Keep colour contrast accessible so the login form stays legible.
- Confirm the branding on both desktop and mobile widths — the sign-in pages are responsive.
- Apply consistent branding to the [notification](notifications.md) templates (email, magic-link) so the full sign-in journey feels like one brand.

## Over the API

Branding fields are part of the realm-settings object at `/admin/realms/{realm}/settings` — there is no separate theming endpoint. The examples below assume you have set `$HELIX_URL` / `$REALM` and logged in — see [Authenticating to the API](../getting-started/api-authentication.md).

The relevant fields are `logoUrl`, `primaryColor`, `backgroundColor`, `welcomeText` and `customCss`. On a freshly seeded realm they are unset:

```bash
curl -s -b cookies.txt "$HELIX_URL/admin/realms/$REALM/settings"
```
```json
{
  "realmId": "acme",
  "displayName": "Acme",
  "logoUrl": null,
  "primaryColor": null,
  "backgroundColor": null,
  "welcomeText": null,
  "customCss": null
}
```

Set them with a settings `PUT` (refresh CSRF after the read):

```bash
# Refresh CSRF after any GET, then PUT (see the auth guide for the helper)
curl -s -b cookies.txt -c cookies.txt "$HELIX_URL/admin/realms/$REALM/settings" >/dev/null
CSRF=$(awk '$6=="XSRF-TOKEN"{t=$7} END{print t}' cookies.txt)

curl -s -b cookies.txt -X PUT \
  -H "Content-Type: application/json" \
  -H "X-XSRF-TOKEN: $CSRF" \
  -d '{
        "displayName": "Acme",
        "logoUrl": "https://cdn.example.com/acme-logo.svg",
        "primaryColor": "#0B5FFF",
        "backgroundColor": "#0B1020",
        "welcomeText": "Sign in to Acme",
        "customCss": ".login-card{border-radius:12px}"
      }' \
  "$HELIX_URL/admin/realms/$REALM/settings"
```

The response echoes the updated `RealmSettingsDto` with the new branding fields.

### Full endpoint set

| Method & path (under `/admin/realms/{realm}`) | Purpose |
| --- | --- |
| `GET /settings` · `PUT /settings` | Read / set branding (`logoUrl`, `primaryColor`, `backgroundColor`, `welcomeText`, `customCss`) as part of realm settings |

See the [API reference](../integration/api-reference.md).

## See also

- [Realm settings](realm-settings.md)
- [Notifications](notifications.md)
- [Multi-factor authentication](../authentication/mfa.md)
