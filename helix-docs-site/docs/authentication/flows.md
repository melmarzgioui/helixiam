# Authentication Flows

Design exactly how people sign in to each realm — from a single password prompt to a multi-step, risk-aware journey — without writing code.

## What it is

Helix IAM authenticates users through a **data-driven flow engine**. A flow is an ordered, named tree of authenticators (username/password, OTP, passkeys, device push, conditional step-up, and more) that the engine executes for every sign-in. Because flows are configuration rather than code, you can model your exact sign-in experience per realm and adapt it as your security posture evolves.

Every flow is built from **built-in authenticators** registered on an extensible authenticator SPI, so the catalogue of available steps grows with the product and with any custom authenticators you register.

## How it works

1. Flows are **named per realm** (each has a stable alias).
2. You **bind** a flow at the realm level to set the default sign-in experience for everyone in that realm.
3. You can **override** the bound flow **per client/application**, so a high-assurance application can demand a stronger journey than the realm default.
4. At sign-in, the engine walks the execution tree, evaluating each authenticator's requirement and collecting challenge state (for example, a pending [step-up](mfa.md) second factor) until the user is authenticated or the flow fails.

The editor gives you two synchronized views over the **same** underlying execution tree, so you never lose work switching between them:

- **Simple view — the "Sign-in journey" stepper.** A linear, business-friendly representation: add, reorder, and remove steps as a journey your users will experience.
- **Advanced view — the flow canvas.** The full execution tree, including sub-flows, requirement settings (required, alternative, conditional, disabled), and branching.

A **live login preview** renders the sign-in screens your flow produces as you edit, so you can validate the experience before binding it.

## In the console

Flows live under **Authentication → Flow editor**. Each realm is bootstrapped with a built-in `browser` flow you can copy from rather than starting blank.

1. Open **Authentication → Flow editor** and click **Create**. Give the flow a clear name (its alias), optionally copying an existing flow as a starting point.
2. In the **Simple** view, add the steps of your sign-in journey (for example: identifier → password → second factor). Reorder and remove steps as needed.
3. Switch to the **Advanced** view when you need sub-flows, alternatives, or a conditional [step-up](mfa.md) branch. Set each step's requirement: required, alternative, conditional, or disabled.
4. Use the **live login preview** to confirm the experience before you commit.
5. Bind the flow as the realm default, or set it as a per-application override so a high-assurance app demands a stronger journey than the rest of the realm.

!!! tip "Start simple, grow into advanced"
    Build the happy path in the Simple stepper, then switch to the Advanced canvas only when you need conditional branches or step-up. Both views write to one tree — there is no migration step.

## Over the API

Flows live under `/admin/realms/{realm}/flows`, and the authenticator registry under `/admin/realms/{realm}/authenticators`. The examples below assume you have set `$HELIX_URL` / `$REALM` and logged in — see [Authenticating to the API](../getting-started/api-authentication.md).

### List flows

`builtIn: true` marks the seeded `browser` flow; your own journeys are `builtIn: false`.

```bash
curl -s -b cookies.txt "$HELIX_URL/admin/realms/$REALM/flows"
```
```json
[
  { "realmId": "acme", "alias": "browser",              "builtIn": true  },
  { "realmId": "acme", "alias": "idp-login-demo",       "builtIn": false },
  { "realmId": "acme", "alias": "helix-example-app-sso","builtIn": false }
]
```

### Fetch one flow with its execution tree

Read a single flow by alias. Each execution carries its `authenticatorId`, `requirement`, `condition` flag, `priority` (order), and optional `config`. A row with a `null` `authenticatorId` is a sub-flow container that groups its children (referenced by `parentId`).

```bash
curl -s -b cookies.txt "$HELIX_URL/admin/realms/$REALM/flows/browser"
```
```json
{
  "realmId": "acme",
  "alias": "browser",
  "builtIn": true,
  "executions": [
    { "executionId": "f75960bf-2af7-4049-bea1-a20fe7ffa415", "parentId": null,                                   "authenticatorId": null,          "requirement": "CONDITIONAL", "condition": false, "priority": 10, "config": {} },
    { "executionId": "10fcb355-7580-440b-a4a8-b9d6143a996b", "parentId": "f75960bf-2af7-4049-bea1-a20fe7ffa415", "authenticatorId": "mfa-enabled", "requirement": "REQUIRED",    "condition": true,  "priority": 10, "config": {} },
    { "executionId": "22d38617-2a64-48d1-87ec-6322250248b7", "parentId": "f75960bf-2af7-4049-bea1-a20fe7ffa415", "authenticatorId": "otp",         "requirement": "REQUIRED",    "condition": false, "priority": 20, "config": {} }
  ]
}
```

### List available authenticators

The registry tells you which `authenticatorId` values you may place in a flow, and each one's factor class and level of assurance (LoA). The list is extensible via the authenticator SPI.

```bash
curl -s -b cookies.txt "$HELIX_URL/admin/realms/$REALM/authenticators"
```
```json
[
  { "id": "otp",           "displayName": "One-Time Password (TOTP)",         "factorClass": "POSSESSION", "levelOfAssurance": 2, "category": "METHOD" },
  { "id": "webauthn",      "displayName": "Passkey (WebAuthn)",               "factorClass": "POSSESSION", "levelOfAssurance": 3, "category": "METHOD" },
  { "id": "push",          "displayName": "Push Approval",                    "factorClass": "POSSESSION", "levelOfAssurance": 6, "category": "METHOD" },
  { "id": "risk",          "displayName": "Adaptive risk-based authentication","factorClass": "NONE",      "levelOfAssurance": 0, "category": "CONDITION" },
  { "id": "mfa-enabled",   "displayName": "User has MFA enabled",             "factorClass": "NONE",       "levelOfAssurance": 0, "category": "CONDITION" }
]
```

### Create a flow

`POST /flows` mints an empty flow, or clones an existing one with `copyFromAlias`. Then `PUT /flows/{alias}` persists the execution tree.

```bash
# Refresh CSRF after any GET, then POST (see the auth guide for the helper)
curl -s -b cookies.txt -c cookies.txt "$HELIX_URL/admin/realms/$REALM/flows" >/dev/null
CSRF=$(awk '$6=="XSRF-TOKEN"{t=$7} END{print t}' cookies.txt)

# Create a new flow, seeded from the built-in browser flow
curl -s -b cookies.txt \
  -H "Content-Type: application/json" -H "X-XSRF-TOKEN: $CSRF" \
  -d '{"alias":"step-up-browser","copyFromAlias":"browser"}' \
  "$HELIX_URL/admin/realms/$REALM/flows"

# Save the execution tree (the full desired state)
curl -s -b cookies.txt -X PUT \
  -H "Content-Type: application/json" -H "X-XSRF-TOKEN: $CSRF" \
  -d '{
        "executions": [
          { "authenticatorId": "otp",  "requirement": "CONDITIONAL", "condition": true, "priority": 20, "config": {} }
        ]
      }' \
  "$HELIX_URL/admin/realms/$REALM/flows/step-up-browser"
```

### Delete a flow

```bash
# Delete — returns 204 No Content (built-in flows cannot be deleted)
curl -s -b cookies.txt -X DELETE -H "X-XSRF-TOKEN: $CSRF" \
  "$HELIX_URL/admin/realms/$REALM/flows/step-up-browser"
```

### Full endpoint set

| Method & path (under `/admin/realms/{realm}`) | Purpose |
| --- | --- |
| `GET /flows` · `POST /flows` | List flows / create a flow (`{alias, copyFromAlias}`) |
| `GET` · `PUT` · `DELETE /flows/{alias}` | Fetch one flow with its tree / save the execution tree / delete |
| `PATCH /flows/{alias}` | Rename a flow's alias |
| `GET /authenticators` | List available authenticators in the registry |

!!! note
    Flows are realm-scoped. Cloning a flow into another realm is a copy, not a shared reference — each realm owns its own journeys.

## See also

- [Multi-factor authentication](mfa.md)
- [One-time passcodes (TOTP/SMS/Email)](otp.md)
- [Passkeys (WebAuthn / FIDO2)](passkeys.md)
- [Device push & mobile app](device-push.md)
- [Risk-based / adaptive authentication](risk-based.md)
- [Password policy & lockout](password-policy.md)
