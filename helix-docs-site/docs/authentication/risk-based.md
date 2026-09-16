# Risk-Based & Adaptive Authentication

Demand more proof only when something looks risky — keep everyday sign-in frictionless, and challenge harder when it counts.

## What it is

Helix IAM supports **adaptive authentication**: the sign-in journey can adjust the level of assurance it requires based on **risk signals** observed at login. When a request looks routine, users sail through; when it looks risky, Helix raises the bar — typically by requiring a [step-up](mfa.md) second factor.

## Why it matters

- **Security where it's needed** — stronger challenges target the riskiest sign-ins, not every user.
- **Low friction by default** — trusted, low-risk logins stay fast, which protects conversion and reduces help-desk load.
- **Policy you control** — you decide what counts as risky and how the flow should respond.

## How it works

1. At sign-in, Helix evaluates the available **risk signals** for the request.
2. Based on that assessment, the flow can **raise the required assurance level** — for example, inserting a step-up factor that a low-risk login would skip.
3. The flow engine carries this decision as part of its [step-up challenge state](mfa.md), so the extra factor is requested only when the risk condition fires.

Adaptive behaviour is expressed inside your [authentication flows](flows.md): a conditional step-up step is gated on the risk assessment, so a single named flow can serve both the fast path and the hardened path.

!!! tip "Pair risk with phishing-resistant step-up"
    When you do challenge for more, make the extra factor a strong one. [Passkeys](passkeys.md) or [device push with number matching](device-push.md) give you phishing-resistant assurance at exactly the moments risk is elevated.

## Scoring and thresholds

The risk engine scores each sign-in and maps the score onto three bands — **low**, **medium**, **high** — split by two thresholds. Each band has a configurable **action**: `allow`, `step_up` (require a stronger factor), or `deny`. By default a low-risk login is allowed, a medium-risk login triggers step-up, and a high-risk login is denied.

## In the console

Adaptive auth has two parts: a realm-level **risk policy** (thresholds and per-band actions), and a conditional step-up step in a [flow](flows.md).

1. Open **Authentication → Risk-based / adaptive** and enable the **risk policy**. Set the medium/high thresholds and the action for each band (allow / step-up / deny).
2. Open **Authentication → Flow editor** and add the **Adaptive risk-based authentication** condition, followed by a conditional [step-up](mfa.md) factor gated on it.
3. Choose the step-up factor — prefer a phishing-resistant one such as [passkeys](passkeys.md) or [device push](device-push.md).
4. Use the **live login preview** to confirm both the low-risk (no challenge) and high-risk (challenge) paths behave as intended, then bind the flow.

!!! note
    Adaptive authentication complements your other controls — it decides *when* to challenge, while [MFA](mfa.md) provides the factors and [password policy & lockout](password-policy.md) hardens the primary credential.

## Over the API

The risk **policy** is a set of fields on the realm-settings resource; the risk **condition** is an authenticator you place in a flow. The examples assume you have set `$HELIX_URL` / `$REALM` and logged in — see [Authenticating to the API](../getting-started/api-authentication.md).

### Read the risk policy

```bash
curl -s -b cookies.txt "$HELIX_URL/admin/realms/$REALM/settings"
```
```json
{
  "realmId": "acme",
  "riskPolicyEnabled": false,
  "riskMediumThreshold": 40,
  "riskHighThreshold": 70,
  "riskLowAction": "allow",
  "riskMediumAction": "step_up",
  "riskHighAction": "deny"
}
```

| Field | Controls |
| --- | --- |
| `riskPolicyEnabled` | Master switch for adaptive authentication |
| `riskMediumThreshold`, `riskHighThreshold` | Score cut-offs between the low / medium / high bands |
| `riskLowAction`, `riskMediumAction`, `riskHighAction` | What each band does: `allow`, `step_up`, or `deny` |

### Update the risk policy

`PUT /settings` takes the **full** settings object — read it first, change the risk fields, then submit the whole document (see [password policy](password-policy.md#update-the-policy) for the pattern).

```bash
# Refresh CSRF after the GET, then PUT
curl -s -b cookies.txt -c cookies.txt "$HELIX_URL/admin/realms/$REALM/settings" >/dev/null
CSRF=$(awk '$6=="XSRF-TOKEN"{t=$7} END{print t}' cookies.txt)

curl -s -b cookies.txt -X PUT \
  -H "Content-Type: application/json" -H "X-XSRF-TOKEN: $CSRF" \
  -d '{
        "riskPolicyEnabled": true,
        "riskMediumThreshold": 40,
        "riskHighThreshold": 70,
        "riskMediumAction": "step_up",
        "riskHighAction": "deny"
      }' \
  "$HELIX_URL/admin/realms/$REALM/settings"
```

### Place the risk condition in a flow

The registry exposes a `risk` authenticator (`category: CONDITION`) — add it before a conditional step-up step so the extra factor fires only when the score is elevated.

```bash
curl -s -b cookies.txt "$HELIX_URL/admin/realms/$REALM/authenticators"
```
```json
[
  { "id": "risk", "displayName": "Adaptive risk-based authentication", "factorClass": "NONE", "levelOfAssurance": 0, "category": "CONDITION" }
]
```

Wire it into the execution tree with `PUT /flows/{alias}` — see [Authentication flows → Over the API](flows.md#over-the-api).

### Full endpoint set

| Method & path (under `/admin/realms/{realm}`) | Purpose |
| --- | --- |
| `GET /settings` · `PUT /settings` | Read / update the risk policy (`riskPolicyEnabled`, thresholds, per-band actions) |
| `GET /authenticators` | Confirm the `risk` condition authenticator |
| `GET /flows/{alias}` · `PUT /flows/{alias}` | Read / save the flow that gates step-up on risk |

## See also

- [Realm settings](../operations/realm-settings.md)
- [Authentication flows](flows.md)
- [Multi-factor authentication](mfa.md)
- [Passkeys (WebAuthn / FIDO2)](passkeys.md)
- [Device push & mobile app](device-push.md)
- [Password policy & lockout](password-policy.md)
