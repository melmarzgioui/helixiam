# Device Push & Mobile App

Turn your users' phones into a trusted authenticator — approve a sign-in, scan to log in on a laptop, or cryptographically sign exactly what they're authorizing.

## What it is

Helix IAM provides a **phone-as-authenticator** factor: an enrolled mobile device becomes a strong, hardware-backed credential. It supports push approval, cross-device QR login, and transaction signing — and you can ship it inside your own branded app using the [mobile SDK](../integration/sdk-mobile.md).

## Capabilities

### Hardware-key device enrolment

A device enrols with **hardware-key attestation**, binding the authenticator to the phone's secure hardware. This proves the credential lives on a genuine, untampered device before it is trusted.

### Cross-device QR login

When a user signs in on a browser, Helix can present a QR code. Scanning it with the enrolled phone confirms the session — letting users authenticate on a laptop or shared screen using the device in their pocket.

### Push approval with number matching

Helix sends a push notification to the enrolled device (over **FCM** for Android or **APNs** for Apple). To approve, the user must enter or tap the **number shown in the browser** — **number matching**. This defeats "push fatigue" and accidental approvals, because a blind tap is no longer enough.

!!! tip "Number matching stops push-bombing"
    Plain "approve/deny" prompts can be spammed until a user taps yes. Requiring the user to match the number displayed in the browser ensures the person approving is the person actually signing in.

### Transaction signing (WYSIWYS)

For high-value actions, Helix supports **transaction signing** with **dynamic linking** — *what you see is what you sign* (WYSIWYS). The exact details of the action (for example, payee and amount) are shown on the device and cryptographically bound to the approval, so the user signs precisely what was requested and nothing can be altered in transit.

## How it works

1. The user enrols their device, which attests with its hardware key.
2. At sign-in (or step-up), Helix sends a push, presents a QR code, or requests a transaction signature.
3. The user confirms on the device — matching a number, scanning a code, or reviewing and signing a transaction.
4. Helix verifies the response and completes the factor.

## Build your own authenticator app

A **[mobile SDK](../integration/sdk-mobile.md)** is available to embed enrolment, push approval, QR login, and transaction signing into a fully branded authenticator app — so the experience carries your name, not a generic one.

## In the console

Device push lives under **Authentication → MFA → Device push**. It is placed in a [flow](flows.md) and delivered through your FCM/APNs push channel.

1. Configure **FCM (Android) / APNs (Apple)** push delivery under [notification providers](../operations/notifications.md).
2. Open **Authentication → Flow editor** and add the `push` (or QR / transaction-signing) step to a sign-in journey, as a primary or [step-up](risk-based.md) factor.
3. Users enrol their device from your authenticator app; each device's push token is then registered so it can receive approvals.

## Over the API

Device push spans **two surfaces**. The device-facing ceremonies (enrol, approve, QR confirm, sign) are **protocol endpoints** the authenticator app calls — no admin session, driven by the [mobile SDK](../integration/sdk-mobile.md). Registering and listing a user's push tokens is on the **admin** surface (session + CSRF). The admin examples assume you have set `$HELIX_URL` / `$REALM` and logged in — see [Authenticating to the API](../getting-started/api-authentication.md).

### List a user's push tokens (admin)

`userId` is a required query parameter.

```bash
curl -s -b cookies.txt \
  "$HELIX_URL/admin/realms/$REALM/messaging/push-tokens?userId=c1a848b2-cf68-45d5-85d1-97101cb702a8"
```
```json
[]
```

### Register a push token (admin)

A device can only receive approvals once its FCM/APNs token is registered. The body is `{userId, platform, token}`.

```bash
# Refresh CSRF after any GET, then POST (see the auth guide for the helper)
CSRF=$(awk '$6=="XSRF-TOKEN"{t=$7} END{print t}' cookies.txt)

curl -s -b cookies.txt \
  -H "Content-Type: application/json" -H "X-XSRF-TOKEN: $CSRF" \
  -d '{
        "userId": "c1a848b2-cf68-45d5-85d1-97101cb702a8",
        "platform": "APNS",
        "token": "a1b2c3…device-push-token"
      }' \
  "$HELIX_URL/admin/realms/$REALM/messaging/push-tokens"
```

### Device-facing endpoints (mobile SDK / protocol)

These are called by the enrolled authenticator app, not by an admin script. The `id` is the pending challenge identifier surfaced in the browser flow.

| Method & path | Purpose |
| --- | --- |
| `POST /device/enroll/start` · `POST /device/enroll` | Begin / complete hardware-attested device enrolment |
| `GET /push/{id}` · `POST /push/{id}/approve` · `POST /push/{id}/deny` | Read / approve (with number match) / deny a push challenge |
| `GET /qr/{id}` · `POST /qr/{id}/confirm` | Read / confirm a cross-device QR login |
| `GET /tx/{id}` · `POST /tx/{id}/sign` · `POST /tx/{id}/consume` | Read / sign (WYSIWYS) / consume a transaction-signing request |

!!! note "Number matching is enforced in the approval body"
    A push approval carries the `selectedNumber` the user tapped, so a blind approve/deny is not enough — see the `ApproveRequest` schema in the [API reference](../integration/api-reference.md).

### Full endpoint set (admin surface)

| Method & path (under `/admin/realms/{realm}`) | Purpose |
| --- | --- |
| `GET /messaging/push-tokens?userId=…` · `POST /messaging/push-tokens` | List / register a user's device push tokens |
| `GET /flows/{alias}` · `PUT /flows/{alias}` | Read / save the flow that presents the push (or QR / tx-signing) step |
| `GET · PUT /messaging/providers` | Configure FCM / APNs push delivery |

## See also

- [Multi-factor authentication](mfa.md)
- [Passkeys (WebAuthn / FIDO2)](passkeys.md)
- [Authentication flows](flows.md)
- [Risk-based / adaptive authentication](risk-based.md)
- [Mobile SDK](../integration/sdk-mobile.md)
- [Notification providers](../operations/notifications.md)
