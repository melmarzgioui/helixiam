# Email delivery

HelixIAM sends security-critical email itself: registration verification, password reset, email-change
confirmation, magic links and one-time codes. This page covers how to choose and configure a transport, how to set
up the sending domain, and how HelixIAM retries, handles bounces, limits its send rate and reports what it does.

1. [Choosing a transport](#1-choosing-a-transport)
2. [The sending domain: SPF, DKIM and DMARC](#2-the-sending-domain-spf-dkim-and-dmarc)
3. [Cloudflare Email Service](#3-cloudflare-email-service)
4. [SMTP: SMTPS versus STARTTLS](#4-smtp-smtps-versus-starttls)
5. [The generic HTTP driver (for custom relays)](#5-the-generic-http-driver-for-custom-relays)
6. [Per-realm configuration (admin API)](#6-per-realm-configuration-admin-api)
7. [Global configuration (properties and environment variables)](#7-global-configuration-properties-and-environment-variables)
8. [Retries, expiry and idempotency](#8-retries-expiry-and-idempotency)
9. [Bounces](#9-bounces)
10. [The send rate cap](#10-the-send-rate-cap)
11. [Metrics and audit events](#11-metrics-and-audit-events)
12. [Troubleshooting by result code](#12-troubleshooting-by-result-code)

The examples use the realm `acme`, the sending domain `example.com` and these shell variables:

```bash
HX=https://idp.example.com          # IDP_BASE_URL
# An admin token, e.g. from the bootstrap service account (HELIX_BOOTSTRAP_CLIENT_ID, see README "Configuration")
TOKEN=$(curl -s -u "$CLIENT_ID:$CLIENT_SECRET" -d grant_type=client_credentials \
  "$HX/realms/master/oauth2/token" | jq -r .access_token)
AUTH="Authorization: Bearer $TOKEN"
```

A bearer token needs no CSRF header. A console session (cookie) does: send `X-XSRF-TOKEN` on every write.

---

## 1. Choosing a transport

Each realm can have its own email provider. A realm without one, and email sent outside a realm (the platform-level
signup and password-reset notifications), use the server's global default. Four drivers exist:

| Driver | Transport | Use it when |
|---|---|---|
| `SMTP` | SMTP with STARTTLS (port 587) or implicit TLS, "SMTPS" (port 465) | You have a mail relay or a provider that offers SMTP, and your host lets you connect out on 587 or 465. |
| `CLOUDFLARE` | Cloudflare Email Service, HTTPS API (port 443) | Your host blocks outbound SMTP ports, or you already use Cloudflare for the sending domain. |
| `HTTP` | One fixed JSON shape over HTTP(S) | You run your own relay service that accepts HelixIAM's payload ([section 5](#5-the-generic-http-driver-for-custom-relays)). Prefer a provider driver when one fits. |
| `LOG` | No delivery: logs the message id and subject (never the body or the recipient) | Local development without a mail server. |

**Hosting restrictions.** Many cloud and hosting providers block outbound port 25 by default, and many block 465
and sometimes 587 too, to stop spam from compromised machines; unblocking takes a support request, or is not offered
at all. Port 443 (HTTPS) is always open, because every web application needs it. An HTTPS API driver such as
`CLOUDFLARE` therefore works wherever HelixIAM can reach the internet, needs no extra egress rule, and goes through
the same egress guard as HelixIAM's other outbound calls. If your network policy (for example the Helm chart's
`networkPolicy`) restricts egress ports, add 587 or 465 (`networkPolicy.extraEgressPorts`) before you use SMTP.

**The admin test endpoint** sends a real email through a realm's provider and answers with the classified result, so
you can check a configuration before users depend on it:

```bash
curl -s -X POST -H "$AUTH" -H 'Content-Type: application/json' \
  "$HX/admin/realms/acme/messaging/providers/EMAIL/test" -d '{"to": "you@example.com"}'
# {"sent":true,"message":"Test email sent.","result":"ACCEPTED","reason":"NONE","diagnostic":"HTTP 200",...}
```

Add `"driver": "SMTP"` (or `CLOUDFLARE`, `HTTP`, `LOG`) to test a provider you have saved but not enabled yet,
before you switch to it. The test email is sent once: it is never retried and never marks a bounce, but the send
rate cap applies.

## 2. The sending domain: SPF, DKIM and DMARC

Receiving mail servers decide whether a password-reset email lands in the inbox, the spam folder or nowhere, largely
from three DNS records of the domain in the **from address** (for example `no-reply@example.com`):

- **SPF** (`TXT` on `example.com`): lists who may send mail for the domain. Include your provider, for example
  `v=spf1 include:<your provider's SPF domain> -all`. Keep a single SPF record per domain, and at most ten DNS
  lookups in it.
- **DKIM** (`TXT` on `<selector>._domainkey.example.com`, or a `CNAME` your provider gives you): the public key the
  provider signs your mail with. Every provider documents its own selector and value.
- **DMARC** (`TXT` on `_dmarc.example.com`): tells receivers what to do with mail that fails, for example
  `v=DMARC1; p=quarantine; rua=mailto:dmarc-reports@example.com`. Start with `p=none` and the `rua` reports, and
  tighten to `quarantine` or `reject` once the reports show only your own senders.

**Alignment.** DMARC passes only when SPF or DKIM passes *for the from domain*: the DKIM signature's domain (`d=`), or
the envelope sender's domain for SPF, must be the from address's domain or a subdomain of it. So use a from address on
a domain you have set up with your provider, not a free-mail address, and not a domain the provider did not sign for.
A dedicated subdomain (for example `auth.example.com`) keeps identity mail's reputation separate from marketing mail.

Check a configuration by sending a test email to a mailbox you control and reading the `Authentication-Results`
header: `spf=pass`, `dkim=pass` and `dmarc=pass`.

## 3. Cloudflare Email Service

The `CLOUDFLARE` driver calls `POST https://api.cloudflare.com/client/v4/accounts/{accountId}/email/sending/send`
with a bearer token.

**Prerequisites**

1. **Onboard the sending domain** in Cloudflare Email Service (in the Cloudflare dashboard, for the account that owns
   the domain's zone). Cloudflare adds the SPF and DKIM records it needs; add a DMARC record as in
   [section 2](#2-the-sending-domain-spf-dkim-and-dmarc). Until the domain is onboarded, sends fail with
   `403` (`TRANSIENT_FAILURE / AUTHENTICATION`).
2. **Create an API token** (My Profile → API Tokens → Create Token → Custom token) with the permission
   **Account → Email Sending → Edit**, limited to the account. No zone permission is needed.
3. **Find the account id**: it is on the account's overview page in the dashboard (and in the dashboard URL,
   `dash.cloudflare.com/<account id>/…`).

**Per realm**

```bash
curl -s -X PUT -H "$AUTH" -H 'Content-Type: application/json' \
  "$HX/admin/realms/acme/messaging/providers" -d '{
    "channel": "EMAIL",
    "driver": "CLOUDFLARE",
    "enabled": true,
    "fromAddress": "no-reply@example.com",
    "fromName": "Acme",
    "config": {"accountId": "0123456789abcdef0123456789abcdef"},
    "secret": "<API token>"
  }'
```

**Globally**, for example in Kubernetes with the token mounted from a Secret (the Helm chart's `email.cloudflare.*`
values do this):

```bash
HELIX_NOTIFICATION_EMAIL_DRIVER=cloudflare
HELIX_NOTIFICATION_EMAIL_FROM_ADDRESS=no-reply@example.com
HELIX_NOTIFICATION_CLOUDFLARE_ACCOUNT_ID=0123456789abcdef0123456789abcdef
HELIX_NOTIFICATION_CLOUDFLARE_API_TOKEN_FILE=/etc/helixiam/email/cloudflare-api-token
```

Settings (`config`): `accountId` (required); `baseUrl` (default `https://api.cloudflare.com/client/v4`, for a proxy
or a test server: `https` only outside the dev profile, no credentials, query or fragment); `connectTimeoutMs`
(default 5000); `readTimeoutMs` (default 15000); `caBundle` (PEM certificates trusted in addition to the JDK roots,
for a TLS-intercepting proxy). The token is the write-only `secret`: it is stored encrypted, never returned by the
API, exported only as a `${ENV_VAR}` placeholder and never logged; an `apiToken` typed into `config` is moved there.

A token that Cloudflare refuses (`401`, `403`) is an operator problem, not a message problem: HelixIAM logs a WARN
line starting with `ACTION NEEDED`, raises `helix_email_provider_auth_failures_total` and emits an
`EMAIL_PROVIDER_AUTH_FAILED` audit event, and keeps retrying the email for up to an hour in case you fix the token.

## 4. SMTP: SMTPS versus STARTTLS

`tlsMode` chooses how the connection is protected:

| `tlsMode` | Default port | What happens |
|---|---|---|
| `STARTTLS_REQUIRED` (default) | 587 | Connects in plain text and upgrades with `STARTTLS` before `AUTH` or any message data. **If the server does not offer STARTTLS, nothing is sent.** |
| `STARTTLS_OPTIONAL` | 587 | Upgrades when the server offers STARTTLS, otherwise continues in plain text. Only for a relay on a trusted network. |
| `IMPLICIT` ("SMTPS") | 465 | TLS from the first byte. Use it for providers that offer only port 465. |
| `NONE` | 25 | Plain text. Only with the `dev` profile: refused on save and at send time in production. |

Certificates are always verified, including the host name. For a private relay with its own CA, give its PEM
certificates in `caBundle` (per realm) or `helix.notification.smtp.ca-bundle-file` (global); there is no "trust all"
switch.

> **Behaviour change.** Before this release, SMTP used STARTTLS when the server offered it and silently fell back to
> plain text when it did not. Now an unset `starttls` / `tlsMode`, and the deprecated `starttls: true`, **require**
> STARTTLS. A relay that does not offer it now fails with `TRANSIENT_FAILURE / CONFIGURATION` ("The SMTP server does
> not offer STARTTLS"). Fix the relay, or set `tlsMode: STARTTLS_OPTIONAL` (or the deprecated `starttls: false`) if
> plain text on that network is acceptable. `tlsMode` wins when both are set.

```bash
curl -s -X PUT -H "$AUTH" -H 'Content-Type: application/json' \
  "$HX/admin/realms/acme/messaging/providers" -d '{
    "channel": "EMAIL",
    "driver": "SMTP",
    "enabled": true,
    "fromAddress": "no-reply@example.com",
    "fromName": "Acme",
    "config": {"host": "smtp.example.com", "port": "465", "tlsMode": "IMPLICIT", "username": "no-reply@example.com"},
    "secret": "<SMTP password>"
  }'
```

Settings (`config`): `host` (required); `port` (default 587, or 465 with `IMPLICIT`); `username`; `tlsMode`;
`starttls` (deprecated: `true` = `STARTTLS_REQUIRED`, `false` = `STARTTLS_OPTIONAL`); `connectTimeoutMs` (default
10000); `readTimeoutMs` (default 20000); `ehloName` (the name HelixIAM greets the server with); `caBundle`. The
password is the write-only `secret`; a `password` typed into `config` is moved there. Every message carries a stable
`Message-ID` header built from HelixIAM's message id.

## 5. The generic HTTP driver (for custom relays)

The `HTTP` driver is for **custom relays**: a service of your own that accepts HelixIAM's fixed payload and hands it
to your mail system. It cannot talk to a provider's own API, which each expect their own request shape; use a
provider driver (`CLOUDFLARE`, `SMTP`) for that. Existing configurations keep working unchanged.

It posts `{from, fromName, to, subject, body, html, contentType, text}` as JSON to `config.url`, with the `secret`
in the `Authorization` header (`Bearer <secret>` by default; change the header with `config.authHeader` and the
prefix with `config.authScheme`) and the message id in an `Idempotency-Key` header, the same on every retry of one
email so the relay can drop a duplicate. `2xx` is accepted; `401`, `403`, `408`, `429` and `5xx` are transient; any
other status is a permanent rejection. The URL passes the egress guard: a private address needs
`HELIX_EGRESS_ALLOWED_PRIVATE_HOSTS`.

```bash
curl -s -X PUT -H "$AUTH" -H 'Content-Type: application/json' \
  "$HX/admin/realms/acme/messaging/providers" -d '{
    "channel": "EMAIL", "driver": "HTTP", "enabled": true,
    "fromAddress": "no-reply@example.com",
    "config": {"url": "https://mail-relay.example.com/send"},
    "secret": "<relay token>"
  }'
```

## 6. Per-realm configuration (admin API)

| Call | Purpose |
|---|---|
| `GET /admin/realms/{realm}/messaging/providers` | The realm's providers (`secretSet` says whether a secret is stored; the secret itself is never returned). |
| `PUT /admin/realms/{realm}/messaging/providers` | Create or replace the provider for a `channel` and `driver`. A blank `secret` keeps the stored one. |
| `DELETE /admin/realms/{realm}/messaging/providers/{channel}/{driver}` | Remove a provider. |
| `POST /admin/realms/{realm}/messaging/providers/{channel}/test` | Send a test: `{"to": "…", "driver": "SMTP"}` → `{sent, message, result, reason, diagnostic, providerMessageId, driver}` (the last five for EMAIL). `driver` is optional: with it, the realm's provider with that driver is tested **even when it is disabled**; without it, the active provider. An unknown driver is a 400 (`fieldErrors.driver`); a known one the realm has not configured answers `sent: false`. |
| `GET /admin/realms/{realm}/users/{userId}` | Includes `emailBounced` and `emailBouncedAt` ([section 9](#9-bounces)). |

Fields of an `EMAIL` provider: `channel` (`EMAIL`), `driver` (`SMTP`, `CLOUDFLARE`, `HTTP` or `LOG`), `enabled`,
`fromAddress` (required except for `LOG`), `fromName`, `config` (the driver's settings, above, plus the optional
`sendLimitPerMinute` of [section 10](#10-the-send-rate-cap)), `secret` (write-only) and `clearSecret`.

**The secret** (the SMTP password, the Cloudflare API token, the HTTP relay token) is write-only; `GET` shows only
`secretSet`. On `PUT`:

| You send | Effect |
|---|---|
| no `secret`, `"secret": null` or `"secret": ""` | The stored secret is **kept**. |
| `"secret": "<value>"` | The stored secret is **replaced**. |
| `"clearSecret": true` (and no `secret`) | The stored secret is **removed**; the provider stays. |
| `"clearSecret": true` with a `secret` | 400, `fieldErrors.clearSecret`: ambiguous. |

A credential typed into `config` (`password`, `apiToken`) counts as a `secret`. A provider that needs its secret to
work cannot be enabled without one: clearing the token of an enabled `CLOUDFLARE` provider, or enabling one that has
none, is a 400 (`fieldErrors.secret`); disable it first, or give a new token. To remove a provider altogether, use
`DELETE`.

```bash
curl -s -X PUT -H "$AUTH" -H 'Content-Type: application/json' \
  "$HX/admin/realms/acme/messaging/providers" -d '{
    "channel": "EMAIL", "driver": "SMTP", "enabled": true, "fromAddress": "no-reply@example.com",
    "config": {"host": "smtp.example.com"},
    "clearSecret": true
  }'
# {"driver": "SMTP", "enabled": true, "secretSet": false, ...}
```

Everything is validated on save: an invalid provider is a `400` with one message per field, for example

```json
{"message": "The Cloudflare account id is required.",
 "fieldErrors": {"config.accountId": "The Cloudflare account id is required.", "secret": "The Cloudflare API token is required to enable this provider."}}
```

A **realm import** applies the same validation: an invalid provider in the document is not saved, and the import
result lists it as a failure of the `messagingProviders` slice with the same field messages
(`The provider EMAIL_CLOUDFLARE is not valid: config.accountId: The Cloudflare account id is required.; …`).

**One active email provider per realm.** A realm can keep several email providers configured (one per driver), but at
most one is enabled: saving a provider with `"enabled": true` makes it the realm's active provider and disables the
realm's other email providers in the same transaction (the `PUT` answers with the saved provider; list the providers
again to see the others' new state). Saving a provider with `"enabled": false` changes no other provider, so an
operator can prepare and test (`"driver"` on the test endpoint) a new provider before switching. A realm import
applies the same rule, entry by entry. A realm saved before this rule with several enabled email providers is repaired
at startup: the most recently saved one stays enabled, the others are disabled, and each is logged as a WARN line
("Realm acme had several enabled EMAIL providers; keeping …"). A provider is read from the database at every send, so
a saved or rotated provider applies at once.

## 7. Global configuration (properties and environment variables)

Every property can be set as an environment variable: upper-case it and replace `.` and `-` with `_`
(`helix.notification.email.retry.max-age` → `HELIX_NOTIFICATION_EMAIL_RETRY_MAX_AGE`). With the Helm chart, use the
`email.*` values (including `email.retry.*`, `email.rateLimit.*` and `email.codes.*`), or `config.extraEnv` for the
others.

**Transport**

| Property | Default | Purpose |
|---|---|---|
| `helix.notification.provider` | `smtp` | `smtp` sends real email (realm provider, else the global default); `log` only logs (development). |
| `helix.notification.email.driver` | `smtp` | The global default driver: `smtp`, `cloudflare` or `log`. |
| `helix.notification.email.from-address` / `.from-name` | the SMTP ones | The global sender. |
| `helix.notification.smtp.host` | *(none)* | The global SMTP server; without it there is no global SMTP. |
| `helix.notification.smtp.port` | 587, or 465 with `IMPLICIT` | |
| `helix.notification.smtp.username` / `.password` | | |
| `helix.notification.smtp.password-file` | | The password in a file (a mounted Secret), read at every send; wins over `.password`. |
| `helix.notification.smtp.tls-mode` | `STARTTLS_REQUIRED` | See [section 4](#4-smtp-smtps-versus-starttls). |
| `helix.notification.smtp.starttls` | `true` | Deprecated; `tls-mode` wins. |
| `helix.notification.smtp.connect-timeout` / `.read-timeout` | `10s` / `20s` | |
| `helix.notification.smtp.ehlo-name` | the host name | |
| `helix.notification.smtp.ca-bundle-file` | | Extra trusted CA certificates (PEM). |
| `helix.notification.smtp.from-address` / `.from-name` | `no-reply@helix.local` / `HelixIAM` | |
| `helix.notification.cloudflare.account-id` | | |
| `helix.notification.cloudflare.api-token` / `.api-token-file` | | The token; the file wins and is read at every send. |
| `helix.notification.cloudflare.base-url` | `https://api.cloudflare.com/client/v4` | `https` outside the dev profile. |
| `helix.notification.cloudflare.connect-timeout` / `.read-timeout` | `5s` / `15s` | |
| `helix.notification.cloudflare.ca-bundle-file` | | |

**Retries** ([section 8](#8-retries-expiry-and-idempotency))

| Property | Default | Purpose |
|---|---|---|
| `helix.notification.email.retry.enabled` | `true` | Retry transient failures at all. |
| `helix.notification.email.retry.delays` | `30s,2m,10m,30m` | The wait before each retry; after the last one the email is given up. |
| `helix.notification.email.retry.max-age` | `1h` | No retry later than this after the first attempt. |
| `helix.notification.email.retry.jitter` | `0.2` | Random spread of each delay (0.2 = ±20 %), so retries after an outage do not all arrive at once. |
| `helix.notification.email.retry.poll-interval` | `5s` | How often each replica looks for due retries. |
| `helix.notification.email.retry.batch-size` | `20` | Retries claimed per poll. |
| `helix.notification.email.retry.lease` | `2m` | A claimed retry whose replica died is claimed again after this. Keep it above the drivers' timeouts. |

**Emailed codes**

| Property | Default | Purpose |
|---|---|---|
| `helix.notification.reset-password.code-ttl` | `1h` | How long a password-reset code works. Single-use; an expired or used code is refused on the reset page. |
| `helix.notification.signup.code-ttl` | `24h` | How long the sign-up verification code works. Single-use. |

The reset and sign-up codes are stored only as their SHA-256 (the plain code is in the email alone), like the
magic-link tokens; each request issues a new code and invalidates the previous one.

**Send rate cap** ([section 10](#10-the-send-rate-cap))

| Property | Default | Purpose |
|---|---|---|
| `helix.notification.email.rate-limit.realm-per-minute` | `120` | Emails per minute per realm (0 = no cap). |
| `helix.notification.email.rate-limit.global-per-minute` | `600` | Emails per minute for the whole server (0 = no cap). |

Secret files are read at every send and realm providers at every send, so rotating a secret needs no restart.

## 8. Retries, expiry and idempotency

- **The first attempt is synchronous.** The flow that sends the email (and the admin test endpoint) gets the real
  result.
- **`TRANSIENT_FAILURE` is retried** after 30 s, 2 min, 10 min and 30 min (each ±20 %), then given up; never later than
  one hour after the first attempt. Every retry resolves the realm's provider again, so a fixed or rotated provider is
  picked up.
- **`PERMANENT_FAILURE` is never retried.** It is logged and audited (`EMAIL_SEND_FAILED`); a bounce also marks the
  address ([section 9](#9-bounces)).
- **No retry past the code's expiry.** Each email that carries a code or link records when it stops working: the
  one-time code 5 minutes, the magic link its lifetime (15 minutes), the verification and email-change links theirs
  (24 hours), the password-reset code 1 hour (`helix.notification.reset-password.code-ttl`) and the sign-up
  verification code 24 hours (`helix.notification.signup.code-ttl`). Every one of these codes and links is also
  single-use and refused by the server once expired.
  A retry that would be due at or after that moment is not queued, and a queued retry found expired (for example
  after downtime) is dropped. The user can always ask for a new email.
- **Persisted.** A retry is stored in the `email_retry` table, so a restart or a new replica picks it up. The rendered
  message (recipient, subject, HTML and text parts, which carry live links and codes) is stored encrypted with the
  database encryption key (`DB_ENCRYPTION`, AES-GCM), like the other secrets; the row is deleted as soon as the email
  is delivered, fails permanently, expires or is given up. Without `DB_ENCRYPTION` (development only: production
  refuses to start without it unless `HELIX_ALLOW_PLAINTEXT_SECRETS=true`) it is stored as plain JSON.
- **Multi-replica safe.** Every replica polls; a replica claims due rows with `SELECT … FOR UPDATE SKIP LOCKED` and a
  lease, so two replicas never send the same retry. A replica that dies mid-retry leaves its rows to be claimed again
  once the lease (2 minutes) has passed.
- **Idempotency: at least once.** An email keeps the same message id on every attempt. SMTP sends it as the
  `Message-ID` header, and the HTTP driver as `Idempotency-Key`, so a receiver or relay can recognise a duplicate.
  The Cloudflare Email Service API takes no idempotency key, so delivery through it is **at least once**: if
  Cloudflare accepted an email but HelixIAM did not get the answer (a timeout, a `5xx` after acceptance, or a replica
  that died after the send), the retry can deliver a second copy. For one-time codes and single-use links a duplicate
  is harmless: both copies carry the same code or link.
- **Not retried:** the admin test email, an email refused by the send rate cap, and `NO_PROVIDER`.

## 9. Bounces

When the provider reports that the recipient's address does not accept mail (`PERMANENT_FAILURE /
RECIPIENT_BOUNCED`: a Cloudflare `permanent_bounces` entry, or an SMTP `5xx` reply to the recipient), HelixIAM marks
that address as bounced on the users of the realm who have it, counts it in `helix_email_bounces_total` and emits an
`EMAIL_BOUNCED` audit event per user.

The admin user API shows it:

```bash
curl -s -H "$AUTH" "$HX/admin/realms/acme/users/$USER_ID" | jq '{email, emailVerified, emailBounced, emailBouncedAt}'
# {"email": "ada@example.org", "emailVerified": true, "emailBounced": true, "emailBouncedAt": 1790503200000}
```

`emailBouncedAt` is epoch milliseconds. The mark is about an address: it disappears when the user's address changes
(through the admin API, the account console or an email-change confirmation) and is cleared when the address is
verified again (the verification link, the email-change link, the signup code, or an admin setting `emailVerified`
from `false` to `true`). HelixIAM keeps sending to a bounced address for now; the mark lets an administrator (and,
later, an "update your email" prompt) act on it.

## 10. The send rate cap

A flood of password-reset or sign-in requests must not exhaust your provider's quota or reputation. On top of the
per-user and per-IP request limits, HelixIAM caps the emails it sends:

- **per realm:** 120 emails per minute by default (`helix.notification.email.rate-limit.realm-per-minute`), or the
  realm's own `sendLimitPerMinute` (1 to 1,000,000) in its `EMAIL` provider's `config`:

  ```bash
  curl -s -X PUT -H "$AUTH" -H 'Content-Type: application/json' \
    "$HX/admin/realms/acme/messaging/providers" -d '{
      "channel": "EMAIL", "driver": "CLOUDFLARE", "enabled": true, "fromAddress": "no-reply@example.com",
      "config": {"accountId": "0123456789abcdef0123456789abcdef", "sendLimitPerMinute": "300"}
    }'
  ```

  A realm that uses the global default provider has the default cap.
- **per server:** 600 emails per minute for all realms together (`…rate-limit.global-per-minute`).

Each cap is a token bucket that refills evenly over the minute, so a burst up to the cap goes out at once. The caps
are counted in each replica's memory: with three replicas the effective cap is up to three times the setting.

An email over a cap is **refused, not dropped silently**: the sender gets `TRANSIENT_FAILURE / RATE_CAPPED` with a
diagnostic naming the cap; nothing reaches the provider and nothing is queued. It is counted in
`helix_email_rate_capped_total{realm,scope}` (`scope` = `realm` or `global`), logged, and audited as
`EMAIL_SEND_RATE_CAPPED` once per realm and minute (not once per email, so a flood does not flood the audit log).
Retries of emails that were already accepted for sending are not capped.

## 11. Metrics and audit events

On `/actuator/prometheus`:

| Metric | Labels | Meaning |
|---|---|---|
| `helix_email_send_total` | `realm`, `driver`, `result` | Every delivery attempt, first or retry; `result` is the status. |
| `helix_email_send_duration_seconds` (histogram) | `realm`, `driver`, `result` | How long each attempt took. |
| `helix_email_retry_total` | `realm`, `outcome` | Retry queue steps: `scheduled`, `delivered`, `rescheduled`, `permanent`, `expired`, `gave_up`. |
| `helix_email_retry_queued` (gauge) | | Emails waiting for a retry. Every replica reports the shared queue: aggregate with `max`, not `sum`. |
| `helix_email_rate_capped_total` | `realm`, `scope` | Emails refused by a send rate cap. |
| `helix_email_bounces_total` | `realm` | Permanent bounces. |
| `helix_email_provider_auth_failures_total` | `realm`, `driver` | The provider refused HelixIAM's credentials: alert on any increase. |

Suggested alerts: any increase of `helix_email_provider_auth_failures_total`; `helix_email_retry_queued` above a
handful for more than ten minutes; a rising share of `helix_email_retry_total{outcome="gave_up"}`.

Audit events (category `ADMIN`, actor `system`, outcome `FAILURE`). The detail carries the message id, status, reason,
the provider's diagnostic, the number of attempts and the stage (`first-attempt`, `retry`, `expired`, `gave-up`);
never the body, the subject, a code, a link or a secret.

| Event | Resource | When |
|---|---|---|
| `EMAIL_SEND_FAILED` | `email` / message id | A permanent failure, a transient failure that cannot be retried, or a retry given up or expired. |
| `EMAIL_BOUNCED` | `user` / user id (or `email` / message id when no user has the address) | A permanent bounce. |
| `EMAIL_SEND_RATE_CAPPED` | `email` / `rate-cap` | The first email over a cap in a minute (detail: `scope`, `limitPerMinute`). |
| `EMAIL_PROVIDER_AUTH_FAILED` | `messaging-provider` / `EMAIL/<driver>` | The provider refused the credentials. |

## 12. Troubleshooting by result code

The test endpoint, the logs and the audit events report `result` (the status) and `reason`:

| Result / reason | Retried | What it means, and what to do |
|---|---|---|
| `ACCEPTED` / `NONE` | – | The provider took the email. If it does not arrive, check the spam folder and SPF/DKIM/DMARC ([section 2](#2-the-sending-domain-spf-dkim-and-dmarc)). |
| `QUEUED` / `NONE` | – | The provider accepted it for later delivery (Cloudflare `queued`). |
| `PERMANENT_FAILURE` / `RECIPIENT_BOUNCED` | no | The address does not accept mail (Cloudflare `permanent_bounces`, SMTP `5xx` to `RCPT`). The user's address is marked bounced; ask the user for a new one. |
| `PERMANENT_FAILURE` / `MESSAGE_REJECTED` | no | The provider refused this email: Cloudflare `400`/`413`, SMTP `5xx` after `DATA` (content policy, size, a from address the provider does not allow). Check the diagnostic, the from address and the template. |
| `PERMANENT_FAILURE` / `AUTHENTICATION` | no | SMTP `5xx` to `AUTH`: wrong username or password. Fix the secret. |
| `PERMANENT_FAILURE` / `CONFIGURATION` | no | Unusable settings: missing host or account id, no token, a `404` from Cloudflare (wrong `accountId` or `baseUrl`), a URL the egress guard refuses, `tlsMode NONE` in production. |
| `PERMANENT_FAILURE` / `PROVIDER_ERROR` | no | Cloudflare answered `200` with `success: false`. Check the diagnostic. |
| `PERMANENT_FAILURE` / `NO_PROVIDER` | no | Neither the realm nor the server has an email provider. Configure one. |
| `TRANSIENT_FAILURE` / `AUTHENTICATION` | yes | Cloudflare `401`/`403` (bad or revoked token, missing permission, domain not onboarded) or SMTP `4xx` to `AUTH`. `ACTION NEEDED` in the log: fix it within the hour and the queued emails still go out. |
| `TRANSIENT_FAILURE` / `RATE_LIMITED` | yes | The provider asked to slow down (Cloudflare `429`, SMTP `450`/`451`/`452`). Check your provider's quota; consider a lower `sendLimitPerMinute`. |
| `TRANSIENT_FAILURE` / `PROVIDER_ERROR` | yes | Cloudflare `408`/`5xx`, another SMTP `4xx`, or a driver failure. Usually passes. |
| `TRANSIENT_FAILURE` / `NETWORK` | yes | Connection refused, DNS, timeout or TLS failure (including an untrusted certificate or a host-name mismatch: add `caBundle` for a private CA). Check egress: is the port open ([section 1](#1-choosing-a-transport))? |
| `TRANSIENT_FAILURE` / `CONFIGURATION` | yes | The SMTP server does not offer STARTTLS while `tlsMode` requires it ([section 4](#4-smtp-smtps-versus-starttls)). |
| `TRANSIENT_FAILURE` / `RATE_CAPPED` | no | HelixIAM's own send rate cap refused the email ([section 10](#10-the-send-rate-cap)). A burst of requests, or a cap set too low. |

Log lines name the message id (`Email <id> of realm acme …`), so one email can be followed from its first attempt to
its last retry. They never contain the body, a code, a link or a secret.
