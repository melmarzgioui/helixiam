# Webhooks

Stream realm events to your own systems in real time — HMAC-signed so you can trust every payload.

## What it is

Webhooks are an outbound **event-listener integration**: subscribe an HTTPS endpoint to a realm's events and Helix IAM fans them out as they happen — logins, user lifecycle changes, admin actions, and more. Each delivery is **HMAC-signed** with the subscription's shared secret, so you can verify it genuinely came from Helix and was not tampered with.

Use them to feed a SIEM, trigger downstream automation, sync a CRM, or build custom audit pipelines.

Each subscription has:

- **name** — a label for the subscription.
- **url** — the HTTPS endpoint that receives deliveries.
- **eventTypes** — a comma-separated list of event types to deliver (e.g. `LOGIN_SUCCESS,LOGIN_FAILURE`).
- **secret** — the HMAC signing secret; write-only. The read response never returns it, exposing only `secretSet` to tell you whether one is configured.
- **enabled** — whether deliveries are active.

## In the console

Webhooks live under **Integration → Provisioning → Webhooks**.

1. Open **Integration → Provisioning → Webhooks**, then click **Create**.
2. Give the subscription a **name** and the **URL** of your receiving endpoint.
3. Choose the **event types** to deliver — for example `LOGIN_SUCCESS` and `LOGIN_FAILURE`.
4. Set a **signing secret** so every delivery is HMAC-signed, and leave the subscription **enabled**.
5. Verify the signature on your endpoint (see below) before trusting any payload.

!!! tip "Respond fast, process async"
    Acknowledge with a `2xx` quickly and hand the payload to a queue. Helix treats non-`2xx` responses as failed deliveries.

## Over the API

Webhook subscriptions live under `/admin/realms/{realm}/webhooks`. The examples below assume you have set `$HELIX_URL` / `$REALM` and logged in — see [Authenticating to the API](../getting-started/api-authentication.md).

### List subscriptions

```bash
curl -s -b cookies.txt "$HELIX_URL/admin/realms/$REALM/webhooks"
```
```json
[]
```

### Create a subscription

```bash
# Refresh CSRF after any GET, then POST (see the auth guide for the helper)
curl -s -b cookies.txt -c cookies.txt "$HELIX_URL/admin/realms/$REALM/webhooks" >/dev/null
CSRF=$(awk '$6=="XSRF-TOKEN"{t=$7} END{print t}' cookies.txt)

curl -s -b cookies.txt \
  -H "Content-Type: application/json" \
  -H "X-XSRF-TOKEN: $CSRF" \
  -d '{
        "name": "siem",
        "url": "https://siem.example.com/hook",
        "eventTypes": "LOGIN_SUCCESS,LOGIN_FAILURE",
        "enabled": true
      }' \
  "$HELIX_URL/admin/realms/$REALM/webhooks"
```
```json
{
  "id": "b14552f0-8f95-40ff-839d-20861c0701f6",
  "realmId": "acme",
  "name": "siem",
  "url": "https://siem.example.com/hook",
  "secret": null,
  "secretSet": false,
  "eventTypes": "LOGIN_SUCCESS,LOGIN_FAILURE",
  "enabled": true,
  "createdAt": null
}
```

!!! tip "Set a signing secret"
    Include a `secret` in the create (or update) body to enable HMAC signing. The read response never echoes it back — `secretSet: true` confirms one is configured.

### Update or delete a subscription

Use the returned `id`:

```bash
# Update (e.g. narrow the event types) — PUT the desired state
curl -s -b cookies.txt -X PUT \
  -H "Content-Type: application/json" -H "X-XSRF-TOKEN: $CSRF" \
  -d '{ "name": "siem", "url": "https://siem.example.com/hook", "eventTypes": "LOGIN_SUCCESS", "enabled": true }' \
  "$HELIX_URL/admin/realms/$REALM/webhooks/b14552f0-8f95-40ff-839d-20861c0701f6"

# Delete — returns 204 No Content
curl -s -b cookies.txt -X DELETE -H "X-XSRF-TOKEN: $CSRF" \
  "$HELIX_URL/admin/realms/$REALM/webhooks/b14552f0-8f95-40ff-839d-20861c0701f6"
```

### Full endpoint set

| Method & path (under `/admin/realms/{realm}`) | Purpose |
| --- | --- |
| `GET /webhooks` · `POST /webhooks` | List / create subscriptions |
| `PUT` · `DELETE /webhooks/{id}` | Update / remove a subscription |

## Verify the signature

Every request carries an HMAC signature computed over the raw body with your subscription's shared secret. Recompute it and compare before trusting the payload.

```ts
import { createHmac, timingSafeEqual } from "node:crypto";

function verify(rawBody: string, signature: string, secret: string) {
  const expected = createHmac("sha256", secret).update(rawBody).digest("hex");
  return timingSafeEqual(Buffer.from(signature), Buffer.from(expected));
}
```

!!! warning "Verify on the raw body"
    Compute the HMAC over the exact bytes you received, before any JSON parsing or re-serialization — and use a constant-time comparison. Reject anything that does not match.

## See also

- [Events & audit log](../manage/events.md)
- [SCIM provisioning](scim.md)
- [API reference](api-reference.md)
