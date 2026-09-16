# Events & audit

The events screen is a persisted, searchable audit trail of what happened in a realm — logins, admin changes, and security-relevant actions — with SIEM emission for downstream analysis.

## What it is

Helix IAM records security and administrative activity to a **persisted, searchable audit log**. Events fall broadly into:

- **Authentication events** — logins, logout, MFA challenges, failures. Every authentication event carries the **realm** it occurred in.
- **Admin events** — create/update/delete operations on realm objects (users, clients, roles, groups, etc.).
- **Security events** — sensitive actions such as credential resets and [admin impersonation](users.md).

### SIEM emission

In addition to the in-product log, events are emitted for your SIEM:

- **stdout JSON** — structured events are always written to standard output for log collectors.
- **HTTP forwarder** — an optional, configurable forwarder pushes events to an external HTTP endpoint.

!!! note
    The Events screen is **read-only**. It is a record of what happened; you cannot edit or delete individual events from the UI. Configure emission and forwarding rather than mutating history.

## In the console

The Events screen lives under the **Compliance & security → Events & audit** nav group. SIEM emission and the HTTP forwarder (webhooks) are configured from the same area.

## Common tasks

1. **Search the audit log** — open **Events** and filter by type, user, client, or time range to investigate activity.
2. **Trace an authentication issue** — find the user's authentication events (which carry the realm) to see successes and failures.
3. **Audit a sensitive action** — confirm credential resets and [impersonation](users.md) are recorded against the responsible admin.
4. **Forward to a SIEM** — enable the HTTP forwarder (in addition to the always-on stdout JSON) to ship events to your security stack.

!!! tip
    Pair the audit log with [Sessions](sessions.md): events tell you what was done, sessions tell you who is currently signed in.

!!! warning
    Retain and ship audit events to durable storage. The in-product view is for investigation; your SIEM or log pipeline is the system of record for long-term retention and tamper-evidence.

## Over the API

The audit log is read over the realm-scoped admin API; emission (stdout + HTTP forwarder) is configured through the audit-config and webhook endpoints. The examples below assume you have set `$HELIX_URL` / `$REALM` and logged in — see [Authenticating to the API](../getting-started/api-authentication.md).

### Read the audit log — `GET /admin/realms/{realm}/events`

Results are paginated (`items` / `page` / `size` / `total`) and filterable by `type`, `actor`, `outcome`, `category`, `page` and `size`:

```bash
curl -s -b cookies.txt "$HELIX_URL/admin/realms/$REALM/events?size=2"
```
```json
{
  "items": [
    {
      "ts": "2026-07-06T12:33:22Z",
      "kind": "audit",
      "category": "ADMIN",
      "type": "ADMIN_DELETE",
      "realm": "acme",
      "actor": "c1a848b2-cf68-45d5-85d1-97101cb702a8",
      "sourceIp": "192.168.65.1",
      "resourceType": "flows",
      "resourceId": "gate-flow",
      "outcome": "SUCCESS",
      "detail": null
    },
    {
      "ts": "2026-07-06T12:33:11Z",
      "kind": "audit",
      "category": "AUTHN",
      "type": "LOGIN_SUCCESS",
      "realm": "acme",
      "actor": "admin",
      "sourceIp": "192.168.65.1",
      "outcome": "SUCCESS"
    }
  ],
  "total": 149,
  "page": 0,
  "size": 2
}
```

Every event carries its `realm`, and authentication events name the `actor` — filter down to one identity's activity, for example, with `?category=AUTHN&actor=admin&outcome=FAILURE`.

### Inspect emission config — `GET /admin/audit/config`

```bash
curl -s -b cookies.txt "$HELIX_URL/admin/audit/config"
```
```json
{
  "enabled": true,
  "transports": ["stdout"],
  "httpUrl": "",
  "httpConfigured": false,
  "authConfigured": false,
  "categories": ["AUTHN", "ADMIN"],
  "timeoutMs": 2000
}
```

`transports` always includes `stdout` (structured JSON, for log collectors); adding the HTTP forwarder flips `httpConfigured` to `true`.

### Forward to a SIEM — `GET` · `POST /admin/realms/{realm}/webhooks`

Register an outbound webhook to push events to your security stack over HTTP. A `secret` signs each delivery so the receiver can verify authenticity (creating one is a **write**, so refresh the CSRF token first):

```bash
curl -s -b cookies.txt "$HELIX_URL/admin/realms/$REALM/webhooks"   # list existing
```
```json
[]
```
```bash
# Refresh CSRF after the GET, then create the forwarder
CSRF=$(awk '$6=="XSRF-TOKEN"{t=$7} END{print t}' cookies.txt)

curl -s -b cookies.txt \
  -H "Content-Type: application/json" -H "X-XSRF-TOKEN: $CSRF" \
  -d '{
        "name": "siem-forward",
        "url": "https://siem.example.com/ingest/helix",
        "secret": "s3cr3t-signing-key",
        "eventTypes": "LOGIN_SUCCESS,LOGIN_FAILURE,ADMIN_DELETE",
        "enabled": true
      }' \
  "$HELIX_URL/admin/realms/$REALM/webhooks"
```

| Method & path | Purpose |
| --- | --- |
| `GET /admin/realms/{realm}/events` | Read the paginated, filterable audit log |
| `GET /admin/audit/config` | Inspect audit emission config (transports, categories) |
| `GET` · `POST /admin/realms/{realm}/webhooks` | List / register HMAC-signed event forwarders |
| `PUT` · `DELETE /admin/realms/{realm}/webhooks/{id}` | Update / delete a webhook |

The audit log is also the primary evidence source for your [compliance program](../compliance/compliance-program.md).

## See also

- [Sessions](sessions.md)
- [Users](users.md)
- [Compliance program](../compliance/compliance-program.md)
- [GDPR & privacy](../operations/gdpr.md)
- [API reference](../integration/api-reference.md)
