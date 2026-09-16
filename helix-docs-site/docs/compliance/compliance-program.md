# Compliance program (PROD-14)

SOC 2 / ISO 27001 and the NL eID accreditations are **formal, audited processes** owned by people and
auditors, not code. This document is the starting map: which Helix capabilities provide the technical
controls, and what the organisational process still requires. It does not, by itself, confer any
certification.

## SOC 2 / ISO 27001 — technical control coverage

| Control area | Helix capability that supports it |
|--------------|-----------------------------------|
| Access control (least privilege) | Realms, fine-grained admin RBAC, per-client scopes & roles |
| Strong authentication | MFA (TOTP/SMS/Email OTP), WebAuthn passkeys, device push, step-up |
| Credential protection | Argon2id password hashing, AES-GCM encryption at rest (`DB_ENCRYPTION`), HIBP breach check, password policy + history |
| Key management | Per-realm signing keys, rotation, KMS/HSM (PKCS#11) support |
| Audit logging | Persisted + searchable audit log, SIEM forwarding, outbound webhooks |
| Session management | Unified SSO sessions, idle/max/remember-me policies, admin revoke, SLO |
| Account lifecycle | SCIM 2.0 in/out, LDAP sync, lockout/brute-force protection |
| Data subject rights (GDPR) | Export/delete user data, consent records |
| Change management | Versioned schema migrations (Flyway), signed releases + SBOM |

## What the program still requires (organisational, external)

- Scope definition + system description; risk assessment.
- Written policies (access, incident response, change management, vendor, BCP/DR).
- Evidence collection over the audit period (typically 3–12 months for SOC 2 Type II).
- An independent auditor (SOC 2 / ISO 27001) — engagement, fieldwork, report.

## NL eID accreditation (external schemes)

Helix ships eIDAS, eHerkenning and DigiD **connectors**; live operation against the production schemes
requires formal admission, not just code:

- **DigiD** — admission via Logius; mandatory annual security assessment (penetration test +
  ENSIA/assessment per the DigiD norm) before connecting to production.
- **eHerkenning** — join as a recognised participant under the Afsprakenstelsel eToegang; conformance
  + audit per the scheme.
- **eIDAS** — connect through the national eIDAS node; cross-border notification process.

The connectors are implemented and configurable from the console; the accreditations are scheme
processes run with Logius / the eToegang scheme / the national node.

## Gathering evidence

An auditor asks for evidence that the controls above actually operate. Two Helix surfaces are your primary sources — both readable over the admin API for scripted, repeatable collection (see [Authenticating to the API](../getting-started/api-authentication.md)):

- **Audit log** — the persisted, searchable record of every authentication and administrative action, filterable by type/actor/outcome and forwardable to your SIEM as the tamper-evident system of record. This is your access-control and change-management evidence. See [Events & audit](../manage/events.md).
- **Realm export** — `GET /admin/realms/{realm}/export` produces a point-in-time snapshot of the realm's configured controls (RBAC, client policies, password policy, MFA requirements) suitable for attaching to a control narrative. See [Backup & disaster recovery](../operations/backup.md#realm-export-portable-config-backup).

Pair these with your written policies and the auditor's period-of-review sampling to build the SOC 2 / ISO 27001 evidence package.

## Status

Technical controls: **implemented** (see the table). Accreditation/audit: **external processes** —
this document is the kickoff map, not a certificate.
