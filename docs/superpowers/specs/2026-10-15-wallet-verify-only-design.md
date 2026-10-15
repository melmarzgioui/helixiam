# EUDI Wallet verify-only / step-up mode (`subject.strategy=NONE`) — design

Date: 2026-10-15. Status: implemented on `feat/wallet-verify-only`. Closes maintainer decision 4 of
`2026-10-09-eudi-wallet-openid4vp.md` (§16.4) and the ROADMAP item "a separate plan for the step-up/verify-only flow".
No human was available; every decision below is recorded with its reason (D1…D12).

## 1. What it is

A wallet identity-provider connection with `subject.strategy=NONE` never signs anyone in, never creates an account and
never links one. It is used by a **flow step** that runs after the user is already identified (password, passkey,
federated login…). The step asks the user's wallet for a PID presentation, checks that the wallet belongs to the
signed-in user, and then:

- raises the session's `acr` to the presentation's level of assurance (`http://eidas.europa.eu/LoA/high`), and
- releases the configured verified attributes (e.g. `age_over_18`, `nationalities`) into the ID token as an
  OIDC-for-Identity-Assurance-style `verified_claims` object, for this login only.

## 2. Invocation

**D1 — a flow authenticator, not an endpoint.** New authenticator `eudi-wallet-verify` (category METHOD, factor
POSSESSION, LoA weight 5). Config: `providerAlias` (required: a `NONE` wallet provider of the realm). It reuses the whole
login machinery that already exists: flows per realm and per client (client-bound flows), `/flow` challenges,
`FlowExecutionState.pendingAcr`, `PendingFederatedLogin.finish` (the single completion choke point) and the ID-token
`acr` binding. A required-action or a dedicated endpoint would have duplicated all of that.

- `authenticate`: no identified user → **failure** (it can never be a first factor). Otherwise it starts a wallet
  transaction of the new purpose `VERIFY`, recording the user as `initiatingUserId`, bound to this browser
  (`BrowserBinding`) with a fresh 256-bit state kept in the flow state, and challenges. `GET /flow` sends the browser
  to the existing wallet page (QR + "Open wallet"); the page's copy says "verify", not "sign in".
- The wallet page's `next` (cross-device) and the wallet's `redirect_uri` (same-device) for a `VERIFY` transaction is
  `/flow/wallet/callback?response_code=…`, which feeds the code to the step (`action`).
- `action`: redeems the code (single use, state + browser binding, constant time), checks the binding (§3), and
  succeeds or fails. A failed step re-renders `flow/wallet-verify` with "try again"; retry starts a new transaction.

**D2 — how an RP asks for it.** Two supported ways, both on existing mechanisms:
1. bind the client to a flow containing the step (Applications → Login flow); every login of that client then ends
   with the wallet step;
2. for a user who already has an SSO session (signed in to another app without the wallet), the RP sends
   **`acr_values`** (e.g. `http://eidas.europa.eu/LoA/high`). New, minimal: when the session's `acr` does not satisfy
   any requested value (exact match, or a higher-or-equal rung on the eIDAS ladder), the authorize endpoint forces
   re-authentication once per request (the `prompt=login` mechanism, so it cannot loop), the client's flow runs, and
   the step raises the `acr`. If the user still does not reach it, the code is issued with the actual `acr` (OIDC Core
   §3.1.2.1: `acr_values` is voluntary) and the RP must check `acr` — documented.

**D3 — no standalone "verify attributes" API for RPs (out of scope).** A back-channel or redirect API that returns
verified attributes to an RP without an OIDC login would be a second presentation protocol with its own RP
authentication, consent, replay and audience rules; OpenID4VP already *is* that protocol and an RP that wants raw
presentations can run its own verifier. Inside the IdP the OIDC login (with `acr_values`) is the one contract RPs
already have. Deferred.

## 3. Binding to the signed-in user (anti-swap)

**D4 — "the wallet that would sign in as you".** A presentation may step up user U only if the same PID, resolved
by the realm's **linked login provider** (`verify.linkedProvider`, a normal wallet connection of the realm), would sign
in as U — computed without any side effect:

1. The subject is computed exactly as the linked provider computes it (`WalletSubjectResolver` with the linked
   provider's `subject` settings and `pid.requestedClaims`, the realm pepper): the administrative-number HMAC, and the
   attribute-tuple HMAC only when the linked provider acknowledges weak subjects.
2. The **number wins**: when the PID carries an administrative number that is linked to a live user, that user must be
   U; a number linked to someone else is refused even if the tuple matches U. The tuple is consulted only when the
   number is absent or unlinked.
3. No link → refused (`link_required`): the user must link the wallet from the account console first (decision 1).
   Never JIT, never a new link, never the upgrade write of the login path.
4. The transaction carries `initiatingUserId`; the callback refuses a redemption whose flow user is not that user,
   or that is not this browser's (binding hash + state + single-use code).
5. A `VERIFY` transaction's code cannot be redeemed as a login or a link and vice versa (purpose check).

**D5 — no "configured attributes" binding.** Matching PID names/birthdate against the profile was rejected: it is
the name-matching the spec forbids for linking (§8.2) and lets a namesake step up an account. Deferred (would need
an explicit risk acknowledgement like `acknowledgeWeakSubject`).

The binding is evaluated at the **callback** (against live links at the moment of use), not when the wallet posts.

## 4. What is released

**D6 — `verified_claims` in the ID token only, from an explicit allow-list.** Provider setting
`verify.releasedClaims` (JSON list). Each entry is either a requested PID claim this verifier maps
(`given_name`, `family_name`, `birthdate`, `nationalities`, `place_of_birth`, `address.*`, `issuing_country`,
`issuing_authority`) or a derived `age_over_NN` (NN 1–150, needs `birthdate` requested; computed from the verified
birth date at verification time, so the birth date itself is not released). **Default: nothing** — the step then
proves possession and raises `acr` only. Claims requested only for binding (`personal_administrative_number`,
`issuing_country`, names for a tuple) are never released unless listed.

```json
"verified_claims": {
  "verification": {"trust_framework": "eidas", "assurance_level": "http://eidas.europa.eu/LoA/high",
                   "time": "2026-10-15T10:00:00Z"},
  "claims": {"age_over_18": true, "nationalities": "NL"}
}
```

- Carried like `acr`: flow state → session attribute (cleared by every new login's `stamp`) → bound to the
  authorization when the code is issued → ID token. Stored as a JSON string attribute and rebuilt into fresh
  `LinkedHashMap`s when the token is encoded (never `Map.of`/`List.of`: SAS's Jackson rejects them).
- `verified_claims` becomes a reserved claim: a protocol mapper cannot forge it.
- Nothing is persisted beyond the session and its authorizations (no user attribute, no link row). Persisting to the
  profile is deferred (D12).

## 5. Config surface and validation

New stored keys (only with `subject.strategy=NONE`; refused otherwise): `verify.linkedProvider`,
`verify.releasedClaims`. `WalletConfigValidator` (400 `{message, fieldErrors}`):

| Rule | Field |
|---|---|
| NONE needs `verify.linkedProvider` (alias syntax), not its own alias | `verify.linkedProvider` |
| NONE + `subject.acknowledgeWeakSubject=true` is refused (the linked provider's setting applies) | `subject.acknowledgeWeakSubject` |
| each released claim is a requested, mapped claim or `age_over_NN` with `birthdate` requested; no repeats | `verify.releasedClaims` |
| `verify.*` set without NONE | `verify.linkedProvider` / `verify.releasedClaims` |

**D7 — NONE is never a first factor**, enforced at runtime in every entry point: hidden from the login page;
`/broker/<alias>` (login start) refuses; the account console's "Link wallet" refuses and does not list it; the
step refuses a provider that is not NONE (a login provider cannot be used to "step up"). Flow saves validate the step:
`providerAlias` required (400). Whether the alias names a NONE provider is checked at run time (providers reload
independently of flows).

## 6. Audit

**D8 —** two AUTHN events, same detail discipline as the login events (no PID value, no subject hash):
`WALLET_VERIFY_SUCCESS` (actor = the user; `{transactionId, alias, format, issuerDn, result, releasedClaims}` with
claim *names* only) and `WALLET_VERIFY_FAILURE` (`reason` = `WalletErrorCode` or `BINDING_MISMATCH` /
`LINK_REQUIRED`). Response-endpoint refusals of a `VERIFY` transaction are `WALLET_VERIFY_FAILURE`, not login
failures. New `WalletErrorCode.BINDING_MISMATCH`.

## 7. Console

**D9 —** in the existing kit (`DESIGN_SYSTEM.md`, no inline styles, i18n EN+NL):
- Identity providers → wallet connection → Policies: subject strategy gets a third choice "Verify only (step-up)";
  choosing it shows "Linked sign-in connection" (select of the realm's other wallet connections) and "Released
  claims" (multi-select of the requested mapped claims + age thresholds), and hides the weak-subject option.
  Validation is a pure function in `walletProvider.ts` (TDD), mirroring the server.
- Authentication → flow editor: the "EU Digital Identity Wallet verification" step gets a provider picker
  (verify-only connections) in the Advanced inspector and the Simple stage; saving is blocked while a step has no
  valid provider (pure, tested `walletVerifyStepErrors`).

## 8. Docs

`docs/eudi-wallet.md` new §12 "Verify-only / step-up"; `CHANGES-1.0.md` next-release entry; `ROADMAP.md` item done.

## 9. Deferred

- Standalone RP "verify attributes" API (D3); attribute-matching binding (D5).
- `verified_claims` in userinfo/access tokens and the OIDC `claims` request parameter; `acr_values_supported` /
  `verified_claims_supported` discovery metadata.
- Step-up without re-entering the first factor (ACR-conditional flow branches à la Keycloak LoA conditions).
- Persisting verified attributes to the user profile (opt-in) (D12).
- (Q)EAA / non-PID credentials (`customCredentialQueries`).
- Terraform support for the new keys.

## 10. Other decisions

- **D10 — transaction purpose `VERIFY`** (fits the existing `purpose varchar(8)`): no schema change, so no Flyway
  migration.
- **D11 — the step's `acr` replaces the login's** only when the step succeeds; a failed/abandoned step leaves no
  `acr` (it lives on the flow state until completion, like the federated `pendingAcr`).
- **D12 — nothing persisted** (session + authorization lifetime only).
- **D13 — no new switch for the flow engine.** A password-first login runs flow steps only with
  `helix.flow-engine.enabled=true` (pre-existing default off); a federated first factor always runs them. Documented,
  not changed (changing the default is a separate, realm-wide decision). The e2e test uses the federated first factor.
- **D14 — the YAML names follow the record** (`subject.linkedProvider`, `subject.releasedClaims`); the stored keys are
  `verify.*` as above (the record component lives on `Subject` to keep the positional `WalletProviderConfig`
  constructor stable).

## 11. Found while implementing

- `/flow` redirects were realm-prefixed twice (`/realms/<r>/realms/<r>/flow`, 403) — redirects are now context-relative.
- A flow step that failed and then challenged again (retry) failed the whole flow; the engine now clears the step's
  earlier failure when it asks again.
