# Helix Admin Console — QA sweep (page-by-page)

Method: live Playwright walk at Vite dev `:5174` → publisher `:8083`, realm `master`, **plus** a full code-level audit of every page component cross-referenced against its Java admin controller. Dated 2026-06-29.

Legend: ✅ verified working · ⏳ intentional roadmap stub · ❌ real defect

## Live-verified working (rendered + primary actions exercised)
| Page | Result |
|------|--------|
| Applications (+ detail: OIDC/SAML/Claims/Login-flow/Settings tabs) | ✅ list, create, protocol tabs, shared claims/flow, cascade-delete, metadata link |
| Users | ✅ list, search, Add user, MFA/status columns, row menu |
| Realm roles | ✅ list, Create role, row menu |
| Authentication (flow editor) | ✅ Simple/Advanced toggle, Password→OTP→Signed-in, resulting-flow, Duplicate/Rename/Delete, Save |
| Identity providers (live) | ✅ list (Corp SSO OIDC, DigiD SAML2), Add provider, protocol/status, row menu |
| Realm settings | ✅ General, Tokens, SSO sessions, Security; Save/Discard |
| Sessions | ✅ live SSO-session rollup (per-app chips), Refresh, expandable, revoke menu |
| Notifications | ✅ SMS/Email/Push/Templates tabs, provider config, Save, Send-a-test |
| Client scopes / Claims / Groups / Events | ✅ list/detail pages — code-audited sound; no API mismatch |

## API endpoints — all verified matched (no 404/400 hazards)
`applications`, `clients`, `claims`, `scopes`, `authz`, `users`, `roles`, `clientRoles`, `groups`, `sessions`, `flows`, `realm`, `messaging`, `audit`, `samlClients` — each console `api/*.ts` call matches its admin controller path/verb/fields.

## Intentional roadmap stubs (the genuine "not implemented" features)
These four nav items deliberately render `InProgressPage` (premium placeholder), backend+UI shipping together later:
- **User federation** — LDAP/AD delegate config (federation SPI exists backend-side).
- **Device & passkeys** — enrolled device credentials / FIDO2 passkeys per user (helix-device + WebAuthn exist backend-side).
- **eID & assurance** — DigiD/eHerkenning/eIDAS + per-client LoA (these connectors are today configured via the **Identity providers** wizard, so this page is partly redundant/informational).
- **Health** — service/queue/key health + login success dashboard (E8.6).

## Audit findings triaged
The background code audit raised ~15 items; on verification the three "MAJOR" ones were **false alarms**:
- ClientDetailPage "tab switches on validation fail" → intentional: it jumps to the tab holding the error after `setAttempted` (good UX).
- ClientDetailPage `catalogue.filter` "undefined" → `catalogue` is `useState<Claim[]>([])`, never undefined; `.catch(()=>undefined)` doesn't set state.
- Mappers "HARDCODED needs no source" → wrong: for HARDCODED, `source` *is* the hardcoded value, so requiring it is correct.
The remainder were speculative defensive-guard nitpicks on always-array values (no runtime path reaches them) — not fixed to avoid churn for non-bugs.

## Minor polish (non-blocking, noted)
- 🟡 Sessions / SAML NameID display the user **UUID** rather than `username` (cosmetic; the rollup keys on user id).

## Stub build-out (in progress)
- ✅ **eID & assurance** — BUILT + live-verified: real page reusing the live `IdentityProviderApi`, filtered to `digid/eherkenning/eidas`, plus a level-of-assurance legend (eIDAS/DigiD/eHerkenning ladders mirroring backend `EidLevelOfAssurance`). Shows the DigiD provider; "Add eID provider" opens the existing wizard.
- ✅ **User federation** — BUILT + live-verified: real page reusing `IdentityProviderApi`, filtered to `ldap/ad`, "Add LDAP / AD" via the existing wizard. (Empty until an LDAP server is added.)
  - Both done by parameterizing `ConnectionsPage` (optional `title/subtitle/addLabel/protocols/aboveContent/empty*` props, defaults preserve the live Identity-providers page) + two thin wrapper pages, wired in `App.tsx`. tsc clean, 48 vitest green.
- ✅ **Device & passkeys** — BUILT + live-verified: new credentials admin slice over the existing user-admin AMQP exchange — `CredentialAdminService` (subscriber) aggregates passkeys/devices/TOTP/HOTP/recovery-codes into a flat secret-free `CredentialSummary` list + revokes one by (type,id) scoped to the owning store; `GET/DELETE /admin/realms/{realm}/users/{userId}/credentials/{type}/{id}`. Console — **restructured (IA)**: there is no standalone Device & passkeys page; clicking a user in the Users table opens a routed **User detail page** (`users/{userId}`) with tabs — **Details** (editable profile + reset/remove), **Role mappings**, **Device & passkeys** (the factor surface), **Sessions** (this user's live SSO sessions, cascade-revocable). The factor surface is a reusable `UserCredentials` component: the **complete factor surface** (all five families always shown, enrolled or "Not set up", + a "N of 5 factor types in use" posture line); singletons (TOTP/HOTP/recovery) revoke from the card header, multi-instance (passkeys/devices) list a row per credential. All four tabs live-verified (sandbox-user: TOTP enrolled, real helix-sandbox session shown). The "Device & passkeys" nav item was removed. Live: sandbox-user shows its TOTP factor (200), revoke route guarded (bogus id → 404). 9 subscriber + 5 console tests green.
  - **Framework gotcha found & fixed:** the mfnr AMQP starter derives a subscriber's binding routing-key from the dashed `@AnonymousListener` queue name by replacing **every** dash with a dot (`AmqpQueueSetup.findMethodListeners`). So a publisher `@AnonymousSender` key must be **fully dot-delimited** — a dash in a multi-word segment (`…list-credentials`) makes the message unroutable and the RPC hangs (HTTP 000). This was also the real root cause of the previously-"flaky" `authorization.user.admin.reset-password` route — **now fixed** in the same pass (`…reset-password` → `…reset.password`); live-verified `PUT …/users/{id}/password` → **204** (was 000). (`UserPublisher`'s own reset key was already all-dots and fine.)
- ✅ **Health** — BUILT + live-verified (E8.6): see below.

## Verdict
Every **implemented** page renders and its primary actions work; no failures and no real code defects found. The only "incomplete features" are the four intentional roadmap stub pages above — each is a substantial build (its own epic). Recommend implementing **Health** first (most self-contained: reads existing service-health endpoints), then **Device & passkeys** (backend already exists).
