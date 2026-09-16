# One-Time Passcodes & Passwordless Email

Add a second factor your users already understand — a six-digit code or a one-tap link — backed by your own delivery channels.

## What it is

Helix IAM supports a full family of one-time passcode and passwordless factors:

- **TOTP** — time-based codes from an authenticator app
- **SMS-OTP** — codes delivered by text message
- **Email-OTP** — codes delivered by email
- **HOTP** — counter-based codes
- **Recovery codes** — single-use backup codes for when a primary factor is unavailable
- **Magic-link passwordless email** — sign in by clicking a one-time link, no password required

SMS-OTP, Email-OTP, and magic links are delivered through your configured **[notification providers](../operations/notifications.md)**, so codes and links go out over the channels and templates you control.

## How it works

### TOTP and HOTP

The user pairs an authenticator app with Helix, which generates a shared secret. The app then produces a rolling code (TOTP, time-based) or a sequenced code (HOTP, counter-based) that the user enters at sign-in. No network connection is needed at challenge time.

### SMS-OTP and Email-OTP

At the challenge step, Helix generates a short-lived code and sends it to the user's verified phone or email through the configured provider. The user types it back to complete the factor.

### Magic-link passwordless email

Instead of a code, Helix emails a one-time link. Opening it completes authentication — useful for low-friction or passwordless journeys.

### Recovery codes

Helix issues a set of single-use recovery codes the user stores safely. Each code authenticates once and is then consumed — a fallback when a phone or authenticator app is lost.

!!! warning "Phishing resistance varies by factor"
    TOTP, SMS, Email-OTP, and magic links can be relayed by a determined attacker. For phishing-resistant assurance, prefer [passkeys](passkeys.md) or [device push with number matching](device-push.md), and reserve OTP factors as convenient secondary or fallback options.

## Enrolment

Users enrol an OTP factor in one of two ways:

1. **Self-service** — from the [account console](../integration/account-console.md), where they scan a QR code (TOTP/HOTP) or confirm a delivery address (SMS/Email).
2. **Required Action** — you queue a *configure OTP* [required action](password-policy.md) so the user must enrol at their next sign-in.

## Step-up

Any OTP factor can be used as a conditional **step-up** second factor inside a [flow](flows.md), challenged only when a sensitive application or elevated [risk signal](risk-based.md) requires it — rather than on every login.

## In the console

OTP factors are placed in a [flow](flows.md); the codes for SMS/Email and magic links are delivered by your [notification providers](../operations/notifications.md).

1. Configure your **[notification providers](../operations/notifications.md)** (SMS, email) so SMS-OTP, Email-OTP, and magic-link messages can be delivered.
2. Open **Authentication → Flow editor** and add the OTP step (`otp`, `sms-otp`, `email-otp`, `hotp`, or `recovery-code`) to a sign-in journey, as **required** or a conditional [step-up](risk-based.md).
3. Users then **enrol** the factor from the [account console](../integration/account-console.md), or you queue a *configure OTP* [Required Action](../manage/users.md) so they enrol at next sign-in.

!!! tip
    Always pair an OTP factor with **recovery codes** so a lost device doesn't lock the user out of their account.

## Over the API

OTP enrolment and challenge are **self-service / protocol** operations — the user scans a QR code or enters a delivered code as part of the sign-in flow — so there is no admin "enrol OTP on behalf of a user" endpoint. What you manage from the admin API is which factors a **flow** presents (the [authenticator registry](flows.md#over-the-api)) and how codes are **delivered** ([notification providers](../operations/notifications.md)). The examples assume you have set `$HELIX_URL` / `$REALM` and logged in — see [Authenticating to the API](../getting-started/api-authentication.md).

### List the OTP-family authenticators

These are the `authenticatorId` values you place in a flow. All are possession factors; recovery codes are LoA 1 (a fallback), the rest LoA 2.

```bash
curl -s -b cookies.txt "$HELIX_URL/admin/realms/$REALM/authenticators"
```
```json
[
  { "id": "otp",           "displayName": "One-Time Password (TOTP)", "factorClass": "POSSESSION", "levelOfAssurance": 2 },
  { "id": "sms-otp",       "displayName": "One-Time Code (SMS)",       "factorClass": "POSSESSION", "levelOfAssurance": 2 },
  { "id": "email-otp",     "displayName": "One-Time Code (Email)",     "factorClass": "POSSESSION", "levelOfAssurance": 2 },
  { "id": "hotp",          "displayName": "One-Time Password (HOTP)",  "factorClass": "POSSESSION", "levelOfAssurance": 2 },
  { "id": "recovery-code", "displayName": "Recovery Code",             "factorClass": "POSSESSION", "levelOfAssurance": 1 }
]
```

### Configure code & link delivery

SMS-OTP, Email-OTP, and magic links go out through the realm's messaging providers and templates. Configure and test them under `/admin/realms/{realm}/messaging` — see [Notification providers](../operations/notifications.md) for the full workflow.

```bash
curl -s -b cookies.txt "$HELIX_URL/admin/realms/$REALM/messaging/providers"
```

### Full endpoint set

| Method & path (under `/admin/realms/{realm}`) | Purpose |
| --- | --- |
| `GET /authenticators` | List the OTP-family factors to place in a flow |
| `GET /flows/{alias}` · `PUT /flows/{alias}` | Read / save the flow that presents the OTP step |
| `GET · PUT /messaging/providers` | Configure SMS / email delivery |
| `GET · PUT /messaging/templates` | Customize the OTP / magic-link message content |

!!! note "Enrolment is on the protocol surface"
    TOTP/HOTP secret provisioning (QR pairing) and code entry happen during login or from the [account console](../integration/account-console.md), not via `/admin`. To compel enrolment, use the *configure OTP* required action on the user.

## See also

- [Multi-factor authentication](mfa.md)
- [Passkeys (WebAuthn / FIDO2)](passkeys.md)
- [Device push & mobile app](device-push.md)
- [Authentication flows](flows.md)
- [Notification providers](../operations/notifications.md)
- [Account console](../integration/account-console.md)
