# Notifications

Wire each realm to your own SMS, email and push providers, and craft the templates that carry one-time codes, magic links and alerts.

## What it is

Helix IAM delivers messages — OTP codes, magic links, push challenges and account notices — through **per-realm messaging providers** that you configure from the console. Nothing is hard-wired to a single vendor: pick the driver that fits each channel.

| Channel | Drivers |
| --- | --- |
| SMS | Twilio, generic HTTP |
| Email | SMTP, HTTP |
| Push | FCM (Android), APNs (Apple) |

These providers power the OTP, magic-link and push delivery used by [multi-factor authentication](../authentication/mfa.md). Configure them per realm so each tenant sends from its own accounts and sender identities.

## Templates

Message bodies are **templates** you author and manage in the console:

- **User-claim passthrough** — interpolate any user attribute with `{{user.*}}` variables (for example `{{user.firstName}}` or `{{user.email}}`).
- **HTML email** — rich, branded email bodies.
- **Magic-link templating** — inject the one-click sign-in link into the message.

Every template can be **previewed** with sample data and **test-sent** to a real address or device before you rely on it in production.

## In the console

1. Open **Manage → Realms → Notifications**.
2. Under **Providers**, choose a channel and driver and enter its credentials.
3. **Test** the provider to confirm delivery.
4. Under **Templates**, edit each message, **preview** it, and **test-send**.

## Over the API

Messaging config lives under `/admin/realms/{realm}/messaging`. The examples below assume you have set `$HELIX_URL` / `$REALM` and logged in — see [Authenticating to the API](../getting-started/api-authentication.md).

### List providers

A freshly seeded realm has no providers configured — delivery is inert until you add one:

```bash
curl -s -b cookies.txt "$HELIX_URL/admin/realms/$REALM/messaging/providers"
```
```json
[]
```

### Configure a provider

`PUT /messaging/providers` upserts the whole provider record for a channel/driver. `channel` and `driver` are required; the `secret` is write-only (the read side reports `secretSet` instead):

```bash
# Refresh CSRF after any GET, then PUT (see the auth guide for the helper)
curl -s -b cookies.txt -c cookies.txt "$HELIX_URL/admin/realms/$REALM/messaging/providers" >/dev/null
CSRF=$(awk '$6=="XSRF-TOKEN"{t=$7} END{print t}' cookies.txt)

curl -s -b cookies.txt -X PUT \
  -H "Content-Type: application/json" \
  -H "X-XSRF-TOKEN: $CSRF" \
  -d '{
        "channel": "EMAIL",
        "driver": "smtp",
        "enabled": true,
        "fromAddress": "no-reply@acme.example",
        "fromName": "Acme",
        "config": { "host": "smtp.acme.example", "port": 587, "username": "acme" },
        "secret": "smtp-password"
      }' \
  "$HELIX_URL/admin/realms/$REALM/messaging/providers"
```
```json
{
  "id": "b2f1c0a4-2c1d-4e9a-9f3b-7a10c5d6e8f2",
  "realmId": "acme",
  "channel": "EMAIL",
  "driver": "smtp",
  "enabled": true,
  "fromAddress": "no-reply@acme.example",
  "fromName": "Acme",
  "config": { "host": "smtp.acme.example", "port": 587, "username": "acme" },
  "secretSet": true
}
```

Send a provider test to confirm delivery (does not persist anything):

```bash
curl -s -b cookies.txt -X POST -H "Content-Type: application/json" -H "X-XSRF-TOKEN: $CSRF" \
  -d '{"to":"you@example.com"}' \
  "$HELIX_URL/admin/realms/$REALM/messaging/providers/EMAIL/test"
```

### Manage templates

The realm ships with seeded templates for OTP, magic-link and push. `{{…}}` placeholders interpolate runtime values and user attributes:

```bash
curl -s -b cookies.txt "$HELIX_URL/admin/realms/$REALM/messaging/templates"
```
```json
[
  { "id": "7d3d015e-7d3c-4277-babd-44966ad861e6", "realmId": "acme", "templateKey": "otp-sms",         "channel": "SMS",   "subject": null,                             "body": "{{realm}} verification code: {{code}} (valid {{ttl}}).", "enabled": true, "html": false },
  { "id": "e99a4b98-641f-4c14-b61c-ef410514b9fa", "realmId": "acme", "templateKey": "otp-email",       "channel": "EMAIL", "subject": "Your {{realm}} verification code","body": "<p>Hi {{user}},</p>…",                                 "enabled": true, "html": true },
  { "id": "8a02ced3-5a8e-4663-aac6-2aa3df73e66c", "realmId": "acme", "templateKey": "magic-link-email","channel": "EMAIL", "subject": "Sign in to {{realm}}",            "body": "<p><a href=\"{{link}}\">Click here…</a></p>",         "enabled": true, "html": true }
]
```

Edit a template with `PUT /messaging/templates`, and render a preview without sending:

```bash
# Preview a template with sample data (returns the rendered subject/body)
curl -s -b cookies.txt -X POST -H "Content-Type: application/json" -H "X-XSRF-TOKEN: $CSRF" \
  -d '{"templateKey":"otp-email","sample":{"user":"Alice","code":"123456","ttl":"5 minutes"}}' \
  "$HELIX_URL/admin/realms/$REALM/messaging/templates/preview"
```

### Full endpoint set

| Method & path (under `/admin/realms/{realm}`) | Purpose |
| --- | --- |
| `GET /messaging/providers` · `PUT /messaging/providers` | List / upsert a channel provider |
| `DELETE /messaging/providers/{channel}/{driver}` | Remove a provider |
| `POST /messaging/providers/{channel}/test` | Send a provider delivery test |
| `GET /messaging/templates` · `PUT /messaging/templates` | List / edit templates |
| `POST /messaging/templates/preview` | Render a template without sending |

See the [API reference](../integration/api-reference.md).

## See also

- [Multi-factor authentication](../authentication/mfa.md)
- [Login theming](theming.md)
- [Realm settings](realm-settings.md)
