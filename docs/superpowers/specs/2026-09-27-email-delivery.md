# HelixIAM feature: pluggable email delivery (Cloudflare Email Service driver + SMTPS)

You are working in the HelixIAM repository (github.com/melmarzgioui/helixiam), a Java 21 / Spring Boot
identity provider with realm-scoped messaging providers (`PUT /admin/realms/{r}/messaging/providers`,
drivers today: SMTP with STARTTLS, a generic HTTP driver, log), email templates, and a global SMTP
fallback (`helix.notification.smtp.*`). Target: the next feature release.

This is a **product feature for every HelixIAM operator**. Don't assume any particular deployment,
customer, domain or cloud.

## Why

HelixIAM sends security-critical email: registration verification, password reset, email-change
confirmation, magic links and OTP codes. Today operators have two options, and both fall short:

1. **SMTP with STARTTLS only.** Many providers accept only implicit TLS ("SMTPS", port 465). Many
   hosting providers block outbound 25 and 465 by default but allow 443. HelixIAM can't use implicit
   TLS at all.
2. **A generic HTTP driver with a fixed JSON body.** It can't talk to real email APIs, which each expect
   their own request shape, authentication and error semantics. So operators put a relay service in
   front of HelixIAM just to translate. The identity server then depends on another service to deliver
   its own password resets.

An identity server should deliver its own mail directly, over the transport the operator's environment
allows.

## Goal

A pluggable email transport layer with:
- **SMTP** supporting both STARTTLS and **implicit TLS (SMTPS)**;
- a native **Cloudflare Email Service** driver over HTTPS;
- a clean driver interface, so API drivers for other providers (Amazon SES, Postmark, SendGrid,
  Mailgun, Resend, …) can be added later without touching callers.

All of it is configurable globally and per realm through the existing messaging-provider API, with
secrets handled safely, clear failure semantics, retries and observability.

## Design

### 1. Transport SPI
- Add an `EmailTransport` interface (or evolve the existing driver abstraction):
  - input: a fully rendered message: from (address, name), to (one or more address/name pairs),
    optional reply-to, subject, HTML body, text body, optional headers the platform allows
    (e.g. `List-Unsubscribe` for non-transactional mail; none today), and a stable message id;
  - result: `DeliveryResult` with status `ACCEPTED | QUEUED | PERMANENT_FAILURE | TRANSIENT_FAILURE`,
    a provider message id when available, and a safe diagnostic string that never contains
    secrets or message bodies.
- Callers (notification delivery) depend only on the SPI. Driver selection is per realm, falling back
  to the global default.
- **Always send a plain-text part.** It must contain every link the HTML part has (verification,
  reset, magic link), not a placeholder like "open this in an HTML-capable client". Generate it from
  the template if the template has none, and cover it with a test.

### 2. SMTP driver: add implicit TLS
- New setting `tlsMode`: `STARTTLS_REQUIRED` (default), `STARTTLS_OPTIONAL`, `IMPLICIT` (SMTPS) or
  `NONE`, the last one for local development only and refused when the server runs in production
  mode. Deprecate the boolean `starttls`, mapping `true` to `STARTTLS_REQUIRED` and `false` to
  `STARTTLS_OPTIONAL`.
- Certificate verification is always on. There's an optional custom CA bundle for private relays, but
  no "trust all" switch.
- Settings: host, port (defaults 587 for STARTTLS and 465 for implicit), username, password (secret),
  connection and read timeouts, and an optional EHLO name.
- Classify failures: SMTP 5xx replies are permanent; 4xx replies and connection or TLS errors are
  transient.

### 3. Cloudflare Email Service driver (HTTPS API)

**Request:**
- `POST https://api.cloudflare.com/client/v4/accounts/{account_id}/email/sending/send`
- Headers: `Authorization: Bearer <api_token>`, `Content-Type: application/json`
- Body:
  ```json
  {
    "from": {"address": "no-reply@example.com", "name": "Example"},
    "to": [{"address": "user@example.org", "name": "User Name"}],
    "reply_to": {"address": "support@example.com"},
    "subject": "…",
    "html": "…",
    "text": "…"
  }
  ```
  - `reply_to` is optional, and `name` is optional everywhere.
  - The address field is named `address`, not `email`; the API rejects `email`.

**Response:**
```json
{
  "success": true,
  "errors": [{"code": 10001, "message": "…"}],
  "result": {"delivered": ["…"], "permanent_bounces": ["…"], "queued": ["…"]}
}
```

**How to classify responses:**

| Response | Result |
|---|---|
| 200 with `success: true` and the recipient in `delivered` | `ACCEPTED` |
| 200, recipient in `queued` | `QUEUED` |
| 200, recipient in `permanent_bounces` | `PERMANENT_FAILURE` (address bounced) |
| 400 or 413 (malformed or too large) | `PERMANENT_FAILURE` |
| 401 or 403 (bad token, sending domain not onboarded) | `TRANSIENT_FAILURE` (fixable by the operator) |
| 429 and 5xx | `TRANSIENT_FAILURE` |
| Network or timeout errors | `TRANSIENT_FAILURE` |

- On 401 and 403, raise an operator-facing alert and metric, not just a log line.
- Read at most 1 MiB of the response.
- The diagnostic is the first error's code and message. Never echo the token.

**Settings:**
- `accountId`
- `apiToken` (secret)
- optional `baseUrl`, defaulting to `https://api.cloudflare.com/client/v4`, for tests and proxies; it
  must be HTTPS except in dev mode
- timeouts

**Required token permission:** Account → Email Sending → Edit. The sender's domain must be onboarded in
Cloudflare Email Service (documented as an operator prerequisite).

### 4. Configuration and secrets
- **Per realm** through the existing API: `PUT /admin/realms/{r}/messaging/providers` with
  `driver: SMTP | CLOUDFLARE | HTTP | LOG`, plus driver-specific settings and the from address and
  name.
  - Validate on save: required fields, `https` base URLs, and ports in range.
  - Unknown drivers get a 400.
- **Globally** through properties or environment variables, for example
  `helix.notification.email.driver=cloudflare`, `helix.notification.cloudflare.account-id` and
  `helix.notification.cloudflare.api-token`, or `…api-token-file` for mounted secrets.
  - Mirror this for SMTP (`password-file`) and document every key.
- **Secrets are write-only:**
  - encrypted at rest with the existing DB encryption;
  - never returned by the API, never exported in realm exports (masked), never logged;
  - `*_FILE` variants for container secrets;
  - rotating a secret needs no restart.
- **Egress:** the Cloudflare driver reaches only the configured HTTPS base URL. It passes through the
  existing egress guard; the public Cloudflare host is fine without a private-address allowlist.

### 5. Delivery behaviour
- **Retries for `TRANSIENT_FAILURE`:** exponential backoff with jitter (for example 30 s, 2 min, 10 min,
  30 min, then give up after about 1 hour). The retry is persisted, so restarts don't lose mail.
- **Codes that expire:** mail carrying a short-lived code or link (OTP, magic link, reset) isn't retried
  past that code's expiry, to avoid sending dead links.
- **No retry for `PERMANENT_FAILURE`.** Record it, and for a bounced address, mark the address on the
  user record as bounced. Admins can see this, and it can drive the "update your email" user flow later.
- **Idempotency:** a stable message id per logical email, so a retry never produces a duplicate
  where the provider supports it. Cloudflare doesn't take one today, so document the at-least-once
  behaviour.
- **Rate limiting:** a per-realm send rate cap (configurable), so a flood of password-reset requests
  can't exhaust the provider quota. It adds to the existing per-user and per-IP request limits.

### 6. Observability and admin tooling
- **Metrics:** `helix_email_send_total{realm, driver, result}`, send latency, retry count, and a gauge
  of queued retries.
- **Audit events:** send failures and bounces. Never include bodies or secrets.
- **Test endpoint:** the existing `POST /admin/realms/{r}/messaging/providers/{channel}/test` sends a
  real test email through the configured driver, and returns the classified result and diagnostic.
- **Docs:** `docs/EMAIL.md`, covering:
  - choosing a transport, and the common hosting restrictions (port 25/465 blocks, and why HTTPS API
    drivers avoid them);
  - SPF, DKIM and DMARC alignment for the from domain;
  - Cloudflare Email Service setup (onboarding the domain, token permissions, account id);
  - the SMTPS versus STARTTLS settings;
  - troubleshooting by result code.

### 7. Backward compatibility
- Existing SMTP and HTTP configurations keep working unchanged. The boolean `starttls` maps as
  described in section 2.
- Keep the generic HTTP driver, but document it as "for custom relays". The provider drivers are
  preferred.

## Tests (write them first)

- **Unit tests per driver**, against a local HTTP mock (Cloudflare) and a local SMTP server:
  - the exact request shape: the `address` field, bearer auth, reply-to, and both text and html parts;
  - every classification row in the Cloudflare table;
  - SMTP `IMPLICIT` against a TLS-only test server, `STARTTLS_REQUIRED` against a server that doesn't
    offer STARTTLS (must fail), and certificate validation failure.
- **Integration tests:** a realm configured with each driver sends verification, reset and magic-link
  mail end to end to the mock servers. The plain-text part contains the link.
- **Retry tests:** transient then success; permanent with no retry; persisted retry surviving a restart;
  an expired code not re-sent.
- **Security tests:**
  - secrets are write-only in API, export and logs (grep the captured logs in tests);
  - the base URL must be HTTPS in production mode;
  - the egress guard applies;
  - validation rejects unknown drivers and missing fields.
- **Admin test endpoint:** returns the classified result.

## Done when

- An operator on a host that blocks ports 25 and 465 can configure a realm with the Cloudflare driver.
  HelixIAM then delivers verification, reset, email-change and magic-link email directly, with correct
  retries, bounce handling, metrics and a working test endpoint.
- An operator with an SMTPS-only provider can use `tlsMode: IMPLICIT` on port 465.
- Every email has a plain-text part containing its links.
- Docs are written, the changelog entry is added, and the full suite is green on both schema paths.
- Report: the files changed, the new settings and API fields, and anything deferred (for example
  further provider drivers).
