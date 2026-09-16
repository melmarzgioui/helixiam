# Password Policy & Lockout

Enforce strong credentials and stop credential-stuffing and brute-force attacks before they reach your applications.

## What it is

Helix IAM gives every realm a complete set of credential-hardening controls: a configurable **password policy**, **password history**, **breached-password detection**, modern **Argon2id** hashing, **account lockout / brute-force protection**, **CAPTCHA**, **concurrent-session limits**, and a **Required Actions** framework that can compel users to remediate at their next sign-in.

## How it works

### Password policy

Define the rules new and changed passwords must satisfy — length, character classes, and similar constraints — per realm. The policy is enforced at registration, at self-service password change, and whenever an admin resets a credential.

### Password history

Helix remembers a configurable number of previous passwords and rejects reuse, so users can't cycle back to a compromised or expired secret.

### Breached-password detection (HIBP)

Passwords are checked against the **Have I Been Pwned** breach corpus using a privacy-preserving k-anonymity range query — the full password is never sent. Known-breached passwords are rejected even when they technically satisfy the policy.

!!! tip "Breach checks beat complexity rules"
    A password that meets every complexity rule can still be in a public breach list. Enabling HIBP catches exactly those credentials that look strong but are already burned.

### Hashing

Credentials are hashed with **Argon2id**, a memory-hard algorithm designed to resist GPU and ASIC cracking. Existing hashes are upgraded transparently as users authenticate.

### Account lockout / brute-force protection

Repeated failed sign-ins trigger temporary lockout with back-off, protecting accounts from online password guessing and credential stuffing. Thresholds and lockout duration are configurable per realm.

### CAPTCHA

Add a CAPTCHA challenge to login and registration to blunt automated attacks and bot-driven account creation.

### Concurrent-session limits

Cap how many simultaneous sessions a user may hold, reducing the blast radius of a shared or stolen credential.

### Required Actions

The Required Actions framework lets you queue tasks a user **must** complete before they finish signing in — for example:

- update password
- verify email
- configure OTP / a second factor

The user is interrupted at their next login and guided through the action.

## In the console

Password, lockout, breach-check, CAPTCHA and session-limit controls are all realm-level settings, edited from **Authentication → Password policy & lockout**.

1. Open **Authentication → Password policy & lockout**.
2. Set the **password rules** — minimum length, required character classes, "not the username", and how many previous passwords to remember.
3. Enable **breached-password detection (HIBP)** to reject known-breached passwords even when they satisfy the rules.
4. Turn on **account lockout** and set the failure threshold, lockout duration, and failure-reset window (or make lockout permanent).
5. Optionally configure a **CAPTCHA** provider and a **concurrent-session limit**.
6. **Save** — changes apply to the next registration, password change, and sign-in.

To force an individual user to remediate, open the user's record and add the **update password** [Required Action](../manage/users.md); it fires at their next sign-in.

!!! warning "Roll out gradually"
    Enabling strict rules or breach checking on an existing realm can block users with non-compliant passwords. Pair it with the **update password** required action so users are guided to remediate rather than simply locked out.

## Over the API

Every control on this page is a field of the realm-settings resource at `/admin/realms/{realm}/settings`. The examples below assume you have set `$HELIX_URL` / `$REALM` and logged in — see [Authenticating to the API](../getting-started/api-authentication.md).

### Read the current policy

```bash
curl -s -b cookies.txt "$HELIX_URL/admin/realms/$REALM/settings"
```
```json
{
  "realmId": "acme",
  "passwordMinLength": 12,
  "passwordRequireUppercase": false,
  "passwordRequireLowercase": false,
  "passwordRequireDigit": false,
  "passwordRequireSpecial": false,
  "passwordNotUsername": false,
  "passwordHistoryCount": 0,
  "breachedPasswordCheck": false,
  "lockoutEnabled": false,
  "maxLoginFailures": 5,
  "lockoutDurationSeconds": 900,
  "failureResetSeconds": 900,
  "permanentLockout": false,
  "captchaProvider": "none",
  "captchaSiteKey": null,
  "captchaSecretKey": null,
  "maxConcurrentSessions": 0,
  "concurrentSessionEvictOldest": true
}
```

The fields map directly to the features on this page:

| Field(s) | Controls |
| --- | --- |
| `passwordMinLength`, `passwordRequire*`, `passwordNotUsername` | Password complexity rules |
| `passwordHistoryCount` | Password history (reuse depth; `0` = off) |
| `breachedPasswordCheck` | Have I Been Pwned breach detection |
| `lockoutEnabled`, `maxLoginFailures`, `lockoutDurationSeconds`, `failureResetSeconds`, `permanentLockout` | Account lockout / brute-force protection |
| `captchaProvider`, `captchaSiteKey`, `captchaSecretKey` | CAPTCHA on login & registration |
| `maxConcurrentSessions`, `concurrentSessionEvictOldest` | Concurrent-session limit (`0` = unlimited) |

!!! note "Argon2id hashing is not configurable here"
    Credentials are always hashed with **Argon2id** and upgraded transparently on next sign-in — there is no toggle to weaken it.

### Update the policy

`PUT /settings` takes the **full** settings object — read it first, change the fields you want, then submit the whole document.

```bash
# Refresh CSRF after the GET, then PUT (see the auth guide for the helper)
curl -s -b cookies.txt -c cookies.txt "$HELIX_URL/admin/realms/$REALM/settings" >/dev/null
CSRF=$(awk '$6=="XSRF-TOKEN"{t=$7} END{print t}' cookies.txt)

curl -s -b cookies.txt -X PUT \
  -H "Content-Type: application/json" -H "X-XSRF-TOKEN: $CSRF" \
  -d '{
        "passwordMinLength": 14,
        "passwordRequireUppercase": true,
        "passwordRequireDigit": true,
        "passwordHistoryCount": 5,
        "breachedPasswordCheck": true,
        "lockoutEnabled": true,
        "maxLoginFailures": 5,
        "lockoutDurationSeconds": 900
      }' \
  "$HELIX_URL/admin/realms/$REALM/settings"
```

### Full endpoint set

| Method & path (under `/admin/realms/{realm}`) | Purpose |
| --- | --- |
| `GET /settings` · `PUT /settings` | Read / update realm settings (password, lockout, CAPTCHA, sessions, and more) |
| `GET` · `PUT /users/{userId}` | Read / update a user, including required actions such as *update password* |

See the [API reference](../integration/api-reference.md) for the complete settings schema.

## See also

- [Realm settings](../operations/realm-settings.md)
- [Authentication flows](flows.md)
- [Multi-factor authentication](mfa.md)
- [Account console](../integration/account-console.md)
- [Risk-based / adaptive authentication](risk-based.md)
