# Multi-Factor Authentication

Raise the bar from "something you know" to "something you have" — and prove who's really signing in.

## What it is

Helix IAM offers a broad, modern set of authentication factors that you compose into your sign-in [flows](flows.md). You decide which factors a realm or application accepts, whether they're required for everyone, and whether they're requested **conditionally** as a step-up only when the moment calls for it.

## Available factors

| Factor | Description | Learn more |
| --- | --- | --- |
| **TOTP** | Time-based one-time passcodes from an authenticator app | [OTP factors](otp.md) |
| **SMS-OTP** | One-time passcode delivered by text message | [OTP factors](otp.md) |
| **Email-OTP** | One-time passcode delivered by email | [OTP factors](otp.md) |
| **HOTP** | Counter-based one-time passcodes | [OTP factors](otp.md) |
| **WebAuthn passkeys (FIDO2)** | Phishing-resistant platform & roaming authenticators | [Passkeys](passkeys.md) |
| **Recovery codes** | Single-use backup codes for account recovery | [OTP factors](otp.md) |
| **Magic-link passwordless email** | Sign in by clicking a one-time link | [OTP factors](otp.md) |
| **Mobile device push** | Approve sign-in on an enrolled phone | [Device push](device-push.md) |

## Step-up authentication

A flow can require an **additional** factor conditionally rather than for every login. Helix carries **step-up challenge state** through the flow, so a journey can authenticate a user with a primary factor and then demand a second factor only when a condition is met — for example a sensitive application, a high-value transaction, or an elevated [risk signal](risk-based.md).

!!! tip "Conditional beats mandatory"
    Requiring a second factor on *every* action creates friction. Use step-up to ask for stronger proof only where it matters, and keep everyday sign-in fast.

## How it works

1. Choose which factors a realm/application accepts.
2. Add the factor as a step in your [sign-in journey](flows.md), setting its requirement (required, alternative, or conditional).
3. Users **enrol** their factor — from the [account console](../integration/account-console.md) or via a [Required Action](password-policy.md) at next login.
4. At sign-in, the flow engine challenges for the factor and, where configured, applies step-up only when the condition fires.

## In the console

The MFA screens live under **Authentication → MFA** (Overview, TOTP & OTP factors, Passkeys, Device push). Factors are placed in a [flow](flows.md); whether MFA is mandatory realm-wide is a realm setting.

1. Open **Authentication → Flow editor** and add the factor as a step in your sign-in journey.
2. Set the step's requirement — **required** for everyone, or **conditional** to challenge only as a [step-up](risk-based.md).
3. To require MFA across the whole realm, turn on **Require MFA** under **Authentication → Password policy & lockout** (the `requireMfa` realm setting).
4. To force enrolment, add the matching **Required Action** (for example, *configure OTP*) on the [user](../manage/users.md).

!!! note "Always offer a recovery path"
    Pair any "have" factor with recovery codes or a second enrolled device so a lost phone or token doesn't lock users out. See [OTP factors](otp.md) for recovery codes.

## Over the API

MFA is composed from two API surfaces: the **authenticator registry** (which factors exist) and **flows** (where you place them). Whether MFA is mandatory realm-wide is the `requireMfa` field of the realm-settings resource. The examples assume you have set `$HELIX_URL` / `$REALM` and logged in — see [Authenticating to the API](../getting-started/api-authentication.md).

### List the available factors

Each authenticator reports a `factorClass` and a **level of assurance** (`levelOfAssurance`) — a higher LoA is a stronger factor, which lets a risk-based flow demand step-up to a minimum strength.

```bash
curl -s -b cookies.txt "$HELIX_URL/admin/realms/$REALM/authenticators"
```
```json
[
  { "id": "otp",           "displayName": "One-Time Password (TOTP)", "factorClass": "POSSESSION", "levelOfAssurance": 2 },
  { "id": "sms-otp",       "displayName": "One-Time Code (SMS)",       "factorClass": "POSSESSION", "levelOfAssurance": 2 },
  { "id": "email-otp",     "displayName": "One-Time Code (Email)",     "factorClass": "POSSESSION", "levelOfAssurance": 2 },
  { "id": "hotp",          "displayName": "One-Time Password (HOTP)",  "factorClass": "POSSESSION", "levelOfAssurance": 2 },
  { "id": "recovery-code", "displayName": "Recovery Code",             "factorClass": "POSSESSION", "levelOfAssurance": 1 },
  { "id": "webauthn",      "displayName": "Passkey (WebAuthn)",        "factorClass": "POSSESSION", "levelOfAssurance": 3 },
  { "id": "push",          "displayName": "Push Approval",             "factorClass": "POSSESSION", "levelOfAssurance": 6 }
]
```

### Require MFA realm-wide

`requireMfa` is one field of the realm-settings resource. `PUT /settings` takes the full object — read it first, then submit the whole document (see [password policy](password-policy.md#update-the-policy) for the full pattern).

```bash
curl -s -b cookies.txt "$HELIX_URL/admin/realms/$REALM/settings" | grep -o '"requireMfa":[^,]*'
```
```json
"requireMfa":false
```

### Wire a factor into a flow

Adding a second-factor step is a flow edit — place the authenticator's `id` (for example `otp` or `webauthn`) in the execution tree with the requirement you want (`REQUIRED` or `CONDITIONAL`). See [Authentication flows → Over the API](flows.md#over-the-api).

### Full endpoint set

| Method & path (under `/admin/realms/{realm}`) | Purpose |
| --- | --- |
| `GET /authenticators` | List available factors and their level of assurance |
| `GET /flows/{alias}` · `PUT /flows/{alias}` | Read / save the execution tree that places a factor |
| `GET /settings` · `PUT /settings` | Read / update `requireMfa` and other realm policy |

## See also

- [Authentication flows](flows.md)
- [OTP factors (TOTP / SMS / Email / HOTP / recovery / magic-link)](otp.md)
- [Passkeys (WebAuthn / FIDO2)](passkeys.md)
- [Device push & mobile app](device-push.md)
- [Risk-based / adaptive authentication](risk-based.md)
- [Notification providers](../operations/notifications.md)
