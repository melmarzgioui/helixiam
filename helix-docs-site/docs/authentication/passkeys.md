# Passkeys (WebAuthn / FIDO2)

Give users the strongest, simplest sign-in available — phishing-resistant, password-free, and backed by hardware.

## What it is

Helix IAM supports **WebAuthn / FIDO2 passkeys** as a first-class authentication factor. A passkey is a cryptographic credential bound to the user's device and to your origin. Because the private key never leaves the authenticator and the signature is scoped to your domain, passkeys are **phishing-resistant by design** — there is no shared secret to steal, replay, or relay.

Helix works with both authenticator types:

- **Platform authenticators** — built into the user's device (Face ID, Touch ID, Windows Hello, Android biometrics).
- **Roaming authenticators** — portable security keys that move between devices over USB, NFC, or Bluetooth.

## Why it matters

- **Phishing-resistant** — credentials are cryptographically bound to your origin, so a lookalike site cannot harvest them.
- **No shared secret** — nothing to breach, reuse, or enter incorrectly.
- **Low friction** — a biometric or a key tap replaces typing codes.
- **Primary or step-up** — usable as the main sign-in factor *or* as a strong [step-up](mfa.md) second factor inside a flow.

!!! danger "A secure origin is required"
    WebAuthn only operates over a secure (**https**) origin. Passkeys cannot be registered or used over plain HTTP. Ensure your sign-in pages are served over TLS before enabling this factor.

## How it works

1. **Registration** — the user's authenticator generates a key pair; the public key is registered with Helix and the private key stays on the device.
2. **Authentication** — Helix issues a challenge; the authenticator signs it (after a local biometric or key-tap gesture) and returns the signature.
3. **Verification** — Helix verifies the signature against the registered public key and the request origin, completing the factor.

## Enrolment

Users enrol passkeys from the **[account console](../integration/account-console.md)**:

1. The user opens their account console and chooses to add a passkey.
2. The browser prompts them to use a platform authenticator (biometric) or a roaming security key.
3. The credential is registered to your realm and ready to use at the next sign-in.

You can also require enrolment with a [Required Action](password-policy.md) so users set up a passkey at their next login.

## Use in a flow

Add a passkey step to a [sign-in journey](flows.md) as either:

- a **primary** factor — for a password-free login experience, or
- a conditional **step-up** factor — challenged only for sensitive applications or elevated [risk](risk-based.md).

## In the console

Passkeys live under **Authentication → MFA → Passkeys**. A passkey is placed in a [flow](flows.md) like any other factor.

1. Open **Authentication → Flow editor** and add a passkey step — `webauthn` for a step-up second factor, or `passkey-login` for a fully passwordless primary login.
2. Set the step's requirement: **primary** (a password-free experience) or a conditional [step-up](risk-based.md) for sensitive apps.
3. Confirm your sign-in origin is served over **https** — WebAuthn will not operate over plain HTTP.
4. Users then **enrol** a passkey from the [account console](../integration/account-console.md), or you queue a Required Action so they enrol at next sign-in.

!!! tip "Encourage a second passkey"
    Prompt users to register more than one passkey (for example, a phone biometric *and* a roaming key) so losing one device doesn't lock them out. Recovery codes provide an additional fallback — see [OTP factors](otp.md).

## Over the API

Passkey **registration and authentication are WebAuthn protocol ceremonies** run in the user's browser during login or from the account console — there is no admin "add a passkey for a user" endpoint (the private key never leaves the device). From the admin API you place the passkey authenticator into a [flow](flows.md#over-the-api). The examples assume you have set `$HELIX_URL` / `$REALM` and logged in — see [Authenticating to the API](../getting-started/api-authentication.md).

### List the passkey authenticators

Both are LoA 3 — the strongest phishing-resistant factors in the registry alongside device push.

```bash
curl -s -b cookies.txt "$HELIX_URL/admin/realms/$REALM/authenticators"
```
```json
[
  { "id": "webauthn",      "displayName": "Passkey (WebAuthn)",   "factorClass": "POSSESSION", "levelOfAssurance": 3, "category": "METHOD" },
  { "id": "passkey-login", "displayName": "Passwordless passkey", "factorClass": "POSSESSION", "levelOfAssurance": 3, "category": "METHOD" }
]
```

- **`webauthn`** — a passkey used as a second/step-up factor after another primary step.
- **`passkey-login`** — a passwordless primary login where the passkey *is* the sign-in.

### Place a passkey in a flow

Add the chosen `authenticatorId` to the flow's execution tree with the requirement you want (`REQUIRED` for primary, `CONDITIONAL` for step-up). See [Authentication flows → Over the API](flows.md#over-the-api) for the `PUT /flows/{alias}` call.

### Full endpoint set

| Method & path (under `/admin/realms/{realm}`) | Purpose |
| --- | --- |
| `GET /authenticators` | List the passkey factors (`webauthn`, `passkey-login`) |
| `GET /flows/{alias}` · `PUT /flows/{alias}` | Read / save the flow that presents the passkey step |

!!! note "Registration is on the protocol surface"
    The WebAuthn create/get ceremonies happen during login and from the [account console](../integration/account-console.md), not via `/admin`. To compel enrolment, add a Required Action to the user.

## See also

- [Multi-factor authentication](mfa.md)
- [Device push & mobile app](device-push.md)
- [OTP factors](otp.md)
- [Authentication flows](flows.md)
- [Account console](../integration/account-console.md)
