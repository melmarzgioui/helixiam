# EUDI Wallet (OpenID4VP verifier) — operator guide

**Status: Experimental.** HelixIAM can act as an OpenID4VP *Verifier* so a realm's users can sign in by presenting a
PID (Person Identification Data) credential from an EU Digital Identity Wallet, instead of (or alongside) a
password. This is a relying-party verifier, not a wallet, and not an issuer. See `docs/FEATURES.md` for the status
line and test count, `helix-iam-server/SECURITY-REVIEW.md` for the threat model, and
`helix-iam-server/DEFERRED-SECURITY-WORK.md` for what is deliberately not done yet.

**"Bring your own registration."** HelixIAM does **not** register you with any national wallet registrar, trust
list operator or scheme owner, and does not obtain an access/registration certificate on your behalf. To accept
real EU wallets you need your own Relying Party registration with your national registrar (or the scheme you are
integrating with), the resulting X.509 access certificate and private key, and your own entry (where applicable)
in a trust list. HelixIAM only consumes what you already hold: you import the access certificate's private key and
chain, and the certificate authorities that sign the PIDs you trust.

---

## 1. Concepts in five lines

- A **wallet provider** is an identity provider connection whose protocol is `eudi-wallet` (also accepted:
  `openid4vp`, `wallet`, case-insensitive) — one per realm, like any OIDC/SAML connection.
- Signing in starts an OpenID4VP **transaction**: HelixIAM mints a signed, encrypted authorization request, the
  user's wallet answers with a **Verifiable Presentation** (SD-JWT VC and/or ISO mdoc), HelixIAM verifies it end to
  end (signature, holder binding, trust chain, revocation status, requested claims) and signs the user in.
- The **subject** HelixIAM signs in as comes from the PID's `personal_administrative_number` when present, else
  from an explicit account link the user makes once while already authenticated (§6).
- Revocation uses the IETF Token Status List; HelixIAM fetches and verifies it itself (§7).

## 2. Setting it up

### 2.1 Required: `DB_ENCRYPTION`

The wallet's verifier access key (its private key) and the per-realm "weak subject" pepper (§6.2) are stored
through the same `AttributeEncryption` JPA converter every other Helix secret column uses
(`helix-iam-server/src/main/java/io/helixiam/persistence/security/AttributeEncryption.java`). Outside the `dev`
profile, importing a verifier key or creating a wallet connection **refuses to proceed** unless `DB_ENCRYPTION` is
set:

- `SoftwareRealmSigningKeys.importKey` refuses with `KeyImportException` ("Database encryption is not configured:
  set DB_ENCRYPTION before importing a verifier signing key") when `AttributeEncryption` is disabled (no
  `DB_ENCRYPTION`) and the deployment profile is not `dev`
  (`helix-iam-server/src/main/java/io/helixiam/authorization/service/key/SoftwareRealmSigningKeys.java:233-239`).
- The per-realm wallet pepper (`realm_wallet_pepper`) is created in plaintext under `dev`, but **fails closed**
  — wallet sign-ins for that realm start erroring — the moment `DB_ENCRYPTION` is set or changed, because there is
  no re-encryption of an existing pepper row (see `docs/eudi-wallet-spec-notes.md` §"Operator notes for the wallet
  subject"). Set `DB_ENCRYPTION` *before* you create the realm's first wallet connection, not after.

Set it the same way as for every other Helix deployment: the `DB_ENCRYPTION` environment variable (`database
.encryption` property).

### 2.2 How console-created connections go live (`helix.federation.store.enabled`)

Identity providers you create through the admin console or the admin API — including a wallet connection — are
persisted to the database and loaded into the live broker registry by the federation store refresher. This is
not specific to the wallet; every admin-API-managed connection (OIDC, SAML, eID, wallet) works this way
(`helix-iam-server/src/main/java/io/helixiam/authorization/federation/FederationConfig.java`,
`FederationStoreRefresher`):

- `helix.federation.store.enabled` defaults to **`true`** (env `HELIX_FEDERATION_STORE_ENABLED`). It used to
  default to `false` because the store was read over AMQP at boot; the store is read in process since RabbitMQ was
  removed, so that reason is gone. Setting it to `false` still turns the store refresh off: connections are then
  saved but never become loginable (only `helix.federation.*` YAML providers and beans are).
- At **startup**, the stored connections of **every realm** are loaded. Restarting the server needs no action.
- Every admin-API create/update/delete refreshes **that write's own realm only**; every other realm's connections
  stay loaded. A failure during that refresh is logged (`WARN`) but the write still succeeds.
- Stored connections are keyed by **(realm, alias)**: each realm sees its own connections, and two realms may both
  use the console's default wallet alias `eudi-wallet`. A realm's login page lists only the connections that serve
  that realm (its own stored ones plus the YAML/bean ones, which serve every realm); a stored connection of another
  realm cannot be started there.
- A stored connection whose secrets cannot be read (for example after `DB_ENCRYPTION` changed) is skipped with a
  `WARN` naming its id; the realm's other connections still load.
- Limits: a refresh after a write reaches the replica that handled the write; other replicas pick the change up at
  their next restart. A realm **import** (`/admin/realms/{realm}/import`) saves its connections without refreshing
  the registry either; they go live at the next restart or the next admin write in that realm.

### 2.3 Through the console

Console → **Identity providers** → **Add identity provider** → **EU Digital Identity Wallet**. The same form
(`helix-dashboard/src/components/WalletProviderForm.tsx`) is shared by the creation wizard and the connection's own
detail page (one tab per settings group), so you can come back later to rotate the verifier key, change trust
anchors or adjust claims. The form can import a new verifier key inline (it calls the same
`/admin/realms/{realm}/verifier-keys` endpoint described below) instead of requiring you to use `curl` first.

### 2.4 Through the admin API

**Step 1 — import your verifier access key.** You already hold this: the EC P-256/384/521 private key and
certificate chain issued when you registered as a Relying Party.

```bash
curl -s -X POST "https://helix.example/admin/realms/$REALM/verifier-keys" \
  -H "Content-Type: application/json" -H "X-XSRF-TOKEN: $CSRF" --cookie "$COOKIES" \
  -d '{
    "name": "primary",
    "privateKeyPem": "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----",
    "certificateChainPem": "-----BEGIN CERTIFICATE-----\n...leaf...\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\n...issuer...\n-----END CERTIFICATE-----"
  }'
```

Returns a key reference such as `software:gov/primary`
(`helix-iam-server/src/main/java/io/helixiam/authorization/controller/admin/VerifierKeyAdminController.java`). The
private key itself is never returned, logged or audited again; `GET` on the same path lists the key's public facts
only. Refusals (bad PEM, wrong curve, RSA, a self-signed leaf, chain order, a duplicate name, missing
`DB_ENCRYPTION` outside `dev`) come back as `400 {message, fieldErrors}`.

**Step 2 — create the identity provider connection**, protocol `eudi-wallet`:

```bash
curl -s -X POST "https://helix.example/admin/realms/$REALM/identity-providers" \
  -H "Content-Type: application/json" -H "X-XSRF-TOKEN: $CSRF" --cookie "$COOKIES" \
  -d '{
    "alias": "eudi-wallet",
    "protocol": "eudi-wallet",
    "displayName": "EU Digital Identity Wallet",
    "enabled": true,
    "config": {
      "accessKeyRef": "software:gov/primary",
      "trustAnchors": "-----BEGIN CERTIFICATE-----\n...PID issuer CA(s)...\n-----END CERTIFICATE-----",
      "credentialFormats": "[\"dc+sd-jwt\",\"mso_mdoc\"]"
    }
  }'
```

`config` is a flat string map (`WalletProviderConfig.fromStored`,
`helix-iam-server/src/main/java/io/helixiam/authorization/federation/wallet/WalletProviderConfig.java:63-98,
250-371`); nested settings are dotted (`pid.requestedClaims`, `statusList.required`, `subject.strategy`,
`limits.maxJwtBytes`, …), lists are JSON arrays of strings. Everything not shown above takes a documented default:
`clientIdScheme` → `x509_hash`; `invocationScheme` → `haip-vp`; `responseMode` → `direct_post.jwt`;
`transactionTtlSeconds` → `300` (60–900 allowed); `pid.requestedClaims` → `given_name`, `family_name`, `birthdate`;
`revocationChecking` → `SOFT_FAIL`; `statusList.required` → `false`; `subject.strategy` →
`ADMINISTRATIVE_NUMBER`; `minimumLoa` → `http://eidas.europa.eu/LoA/high`. `WalletConfigValidator` rejects an
invalid combination with `400 {message, fieldErrors}` naming the field, same shape as every other admin write
(`AdminValidationAdvice`).

## 3. Transaction store: Redis vs in-memory

Each wallet login's in-flight state (nonce, decryption key, bound-browser hash, DCQL query, TTL) lives in a
`WalletTransactionStore`, chosen automatically at boot
(`FederationConfig.WalletTransactionStores`,
`helix-iam-server/src/main/java/io/helixiam/authorization/federation/FederationConfig.java:143-180`):

- **Redis-backed**, when either `helix.iam.session-store=redis` or `helix.iam.token-store=redis` — shared by every
  replica, so a cross-device (QR) login that lands on a different pod from the one that started it still works.
- **In process memory**, otherwise (the `@ConditionalOnMissingBean` default).

**Multi-replica warning:** the in-memory store only works correctly with exactly one replica. If neither the
session nor the token store is Redis and the process is not running under the `dev` profile, startup logs a
`WARN`:

> EUDI wallet logins keep their transactions in process memory (neither `HELIX_SESSION_STORE` nor
> `HELIX_TOKEN_STORE` is redis). With more than one replica a wallet login fails whenever the wallet's requests
> reach another replica: run one replica, or use Redis for the session or token store.

This is specifically checked against `helix.iam.session-store=queue` (the PostgreSQL session store, the project's
other multi-replica setup) outside `dev`
(`FederationConfig.java:174-179`, `warnsAboutReplicas`). If you run more than one HelixIAM replica, put the wallet
transaction store on Redis (by putting the session or token store on Redis) — there is no separate knob for it.

## 4. Trusted proxies / allowed hosts

**Not present on this branch.** `RateLimitFilter` resolves the caller's IP from `X-Forwarded-For` (first hop) or
`X-Real-IP` with no trusted-proxy allow-list
(`helix-iam-server/src/main/java/io/helixiam/authorization/security/ratelimit/RateLimitFilter.java:149-151`), so a
client that reaches HelixIAM directly (no proxy, or an untrusted one) can forge a different apparent IP per request
and evade the wallet-start/login rate limiters. There is no `trustedProxies`/`allowedHosts` setting anywhere in
this codebase as of this branch — those live on a separate, not-yet-merged security branch. Put HelixIAM behind a
proxy you trust to set (and strip any client-supplied) `X-Forwarded-For`, and do not expose it directly to
untrusted clients until that hardening lands. See `helix-iam-server/DEFERRED-SECURITY-WORK.md`.

## 5. Status-list host allow-listing and SSRF

Every status-list fetch goes through `OutboundUrlGuard` — a `status_list.uri` must be `https`, must not resolve to
loopback/private/link-local/metadata addresses, and (optionally) must match `statusList.allowedHosts` if you set
it. This is the same egress guard every other admin-configurable outbound HTTP call in HelixIAM uses. See
`helix-iam-server/SECURITY-REVIEW.md` §"SSRF via status lists" for the detail.

## 6. The subject: "administrative number, else link"

### 6.1 The rule

HelixIAM resolves a wallet sign-in to a local account in this order
(`WalletLinkService.decide`/`decideNumber`,
`helix-iam-server/src/main/java/io/helixiam/authorization/federation/wallet/WalletLinkService.java:189-219`):

1. If the PID carries `personal_administrative_number` **and** that number is already linked to a user of the
   realm → sign in as that user.
2. If the number is **not** linked, but the same holder's weak attribute-tuple (§6.2) **is** linked → sign in as
   that tuple's user, and (only after the whole login, including any step-up, has actually succeeded) **upgrade**
   the link by also claiming the number for that user, so future sign-ins use the stronger number subject. A login
   that fails after this point never creates the upgrade (`WalletLinkService.PendingLink` /
   `WalletPendingLinkCommit`, `commitPendingLink` is only ever called post-success).
3. If the number is unlinked and has no linked tuple, and the realm's `AccountLinkingPolicy.jitProvision()` allows
   it → just-in-time provision a new user and link the number.
4. If the PID carries **no** `personal_administrative_number` at all → there is nothing to JIT-provision from. The
   wallet **cannot create an account by itself**; the user must sign in by some other means first and link the
   wallet from an already-authenticated session (`POST /account/wallet/link`,
   `AccountWalletController`). This is a maintainer decision (spec §16.1), not a bug: identity proven only by a
   repeatable attribute tuple is too weak to auto-create accounts on.

### 6.2 The weak-tuple fallback and its stability caveat

When an operator explicitly opts in (`subject.acknowledgeWeakSubject=true`), a PID *without* an administrative
number can still be **linked** (never auto-created) via an HMAC of a fixed attribute tuple: `issuing_country`,
`family_name`, `given_name`, `birthdate`, plus `place_of_birth.country`/`.region`/`.locality` **exactly when**
`pid.requestedClaims` includes `place_of_birth` for that provider. The HMAC key is a per-realm pepper
(`realm_wallet_pepper`, encrypted — see §2.1); nothing about the tuple is ever logged.

**Stability caveat — read this before changing `pid.requestedClaims`:** the tuple's field set is fixed by
*configuration*, not by what a given PID happens to contain. **Adding or removing `place_of_birth` in
`pid.requestedClaims` changes every tuple subject this provider computes, and orphans every existing tuple link.**
Affected users keep their account but must link their wallet again; this does not affect administrative-number
links. There is no warnings channel in the admin API for this today — `WalletProviderConfig.Subject`'s javadoc and
this document are where it is written down.

**Residual risk:** two different people who share the same attribute tuple (same name, birthdate, country of
issuance, and configured place-of-birth parts) are indistinguishable to this fallback. If one of them has linked
their wallet, the other's wallet resolves to the *same* account. This is why the fallback is opt-in
(`acknowledgeWeakSubject`) and documented as a residual risk in `SECURITY-REVIEW.md`, not treated as a bug to fix —
there is no stronger subject available without the administrative number.

**Upgrade path:** once a user with a tuple-linked account later presents a PID carrying
`personal_administrative_number`, §6.1 step 2 above automatically strengthens their link to the number, without a
new account being created and without any explicit admin action.

### 6.3 Linking limits inherent to cross-device flows

- **QR relay window: 300 s by default** (`transactionTtlSeconds`, 60–900 configurable). A QR code scanned by a
  wallet after the transaction's TTL has elapsed is simply an expired, unknown transaction — the wallet page
  reports "expired or unknown" rather than a specific reason (deliberately less precise, so a transaction ID is
  not confirmed to exist to an unauthenticated prober).
- **Reverse linking-CSRF:** a cross-device "Link wallet" flow (started from an authenticated account-console
  session, completed by scanning a QR with a phone) binds the *browser that started it*, not the browser that
  finishes it — that is the whole point of cross-device. A malicious page cannot forge the completion (the
  response is redeemed server-side against the transaction's own binding, and `helixState` never reaches the
  wallet — see `SECURITY-REVIEW.md`), but an attacker who can get a *victim's already-authenticated browser* to
  open a QR/link the attacker generated could potentially get the victim to link the attacker's wallet to the
  victim's account. Mitigate this the way any CSRF-adjacent, user-interaction-gated flow is mitigated: only trust
  "Link wallet" starts that originate from your own account console, and treat this as an inherent limit of
  cross-device presentation protocols (also true for same-device QR scanning via an arbitrary camera app) rather
  than something this release can fully close.

## 7. Credential status (revocation): fail-open vs fail-closed

Token Status List (IETF `draft-ietf-oauth-status-list-21`) semantics are **asymmetric by design**
(`TokenStatusListClient`, see also the "Trust and revocation" section of
`docs/superpowers/plans/2026-10-09-eudi-wallet-phase2-summary.md`):

- **Fails CLOSED always**, regardless of `statusList.onUnavailable`: anything that proves the status list itself
  cannot be trusted — a bad signature, an untrusted or expired certificate chain, a wrong `typ`/`alg`, a `sub`
  that does not match the fetched `uri`, or a URI refused by policy (non-`https`, blocked by `OutboundUrlGuard`,
  or not in `statusList.allowedHosts`) *before any fetch is attempted*. A list you cannot trust, or are not
  allowed to fetch, is never treated as merely "unavailable" — it is refused outright
  (`STATUS_UNAVAILABLE`/`ISSUER_UNTRUSTED`).
- **May fail OPEN, only when `statusList.onUnavailable=FAIL_OPEN_WITH_AUDIT`**, and only for genuinely transient
  availability problems: a connection/read timeout, a 5xx, a DNS resolution failure, or a thread interruption
  during the fetch. Even then, the verifier emits an audit entry (`WALLET_STATUS_CHECK_FAILED` /
  `UNAVAILABLE_ACCEPTED`) so the operator can see that a login proceeded without a revocation check.
- The **default** is `onUnavailable=FAIL_CLOSED` (so an unreachable status list blocks sign-in by default);
  `statusList.required=false` (so a PID that carries no `status` claim at all is still accepted — most short-lived
  PIDs do not bother with one).

### 7.1 The §6.5 mdoc status-list-signer rule, and the bypass that was fixed

ISO 18013-5 §6.5 requires that the entity signing an mdoc's status list be verifiably related to the entity that
signed the credential's MSO (`IssuerAuth`). HelixIAM enforces this on the **PKIX-validated** chain and its trust
anchor, never on the raw, attacker-controlled `x5chain` bytes presented in the response: the status list's signer
must chain to the MSO signer's own issuing CA. An earlier implementation checked this on the unvalidated chain,
which an attacker could defeat by appending an unrelated (but separately "valid-looking") anchor to the presented
`x5chain` — that bypass was found and fixed before this feature shipped (task-19-review.md, Critical finding,
fix verified by an independent adversarial re-review).

**Known, accepted residual case:** when a status list's signer and the MSO's own signer (the `IssuerAuth` DS
certificate) chain to a **shared root** that *also directly issues DS certificates itself* (rather than through a
dedicated intermediate CA for status lists), the rule as implemented passes — the list signer and the DS
certificate share an issuing CA in the strict sense required. This matches how most real-world issuers operate
(a single IACA anchor per issuer, used for everything that issuer signs) and is not treated as a defect, but it
means the rule's protection narrows to "a status list is signed by *something this issuer's own CA vouches for*",
not "the exact same key that signed this credential."

## 8. Limitations

- **No W3C Digital Credentials API (`dc_api`/`dc_api.jwt`) yet.** Only the redirect-based (same-device) and QR
  (cross-device) OpenID4VP flows are implemented. The DC API is the EU wallet ecosystem's own recommended
  cross-device path and is planned for a later phase (see "Roadmap" in `ROADMAP.md`).
- **Cross-device QR vs ARF guidance.** The spec this feature was built against requires cross-device QR support;
  separate EUDI ARF guidance (OIA_08c) recommends that conformant EU wallets *not* support redirect-based
  cross-device flows at all. Both positions are documented, unresolved, and will be revisited once this is tested
  against a real conformant EU wallet.
- **No trusted-list automation.** Trust anchors (`trustAnchors`) are PEM certificates you paste in yourself; there
  is no ETSI TS 119 612 trusted-list fetcher. Keep your configured anchors current manually.
- **`deviceMac` is rejected outright** (`HOLDER_BINDING_INVALID`,
  `MdocPresentationVerifier.java:469-470`) — only `deviceSignature` (asymmetric holder binding) is accepted for
  mdoc. This is deliberate: MAC-based device authentication needs a reader key the redirect-based flow here has
  no way to establish (the spec notes call out why in their mdoc section), not an oversight.
- **The mdoc/CBOR interop test vector is self-made, not from a certified source.** The ISO 18013-5 2021 edition is
  paywalled and was not read; the mdoc/COSE structures used here come from OpenID4VP's Annex B and the public
  2nd-edition working draft only. A Phase 4 interop run against real wallets/issuers is the place this would be
  caught if something is subtly wrong.
- **No HSM/KMS key provider.** The verifier access key lives in `RealmSigningKeys`' software (DB-encrypted)
  implementation only; a PKCS#11/KMS provider is an unimplemented SPI seam, not a config option today.
- **DigiD-style eID caveats apply by analogy, not directly.** This feature is not DigiD/eHerkenning/eIDAS SAML
  brokering (that is `authorization/federation/eid`) — it is a separate, OpenID4VP-based path to the same kind of
  government-issued identity. If you also run eID connectors in the same realm, review `docs/FEATURES.md`'s eID
  caveats separately; they do not carry over automatically (the wallet's LoA is always asserted as the eIDAS
  `high` ladder rung once a presentation verifies — see `docs/eudi-wallet-spec-notes.md`, Task 20 ruling — there is
  no separate `substantial` tier for wallet logins today).
- **What the user is told when a wallet login fails.** The wallet page (and its status endpoint's `reason`) names
  one of four plain-language kinds only: `declined` (the user said no in the wallet), `not_accepted` (a credential
  was shared but refused: untrusted, revoked, expired, not bound to the wallet, not the PID asked for), `expired`
  (the request ran out of time) or `technical` (anything else). The specific check is in the audit log and the server
  log, never in the browser.
- **Audit of logins that step up.** Every wallet login transaction gets one `WALLET_LOGIN_SUCCESS` or
  `WALLET_LOGIN_FAILURE` event (AUTHN category, detail `{transactionId, alias, format, issuerDn, result, reason}`).
  When the realm's post-login flow asks for a second factor (an MFA-enabled user, a risk step), the event is written
  when that step ends: `WALLET_LOGIN_SUCCESS` names the user it signed in; a login refused after the step
  (for example its pending wallet link was taken meanwhile) is a `WALLET_LOGIN_FAILURE`. A wrong code is a retry,
  not an end. A step-up the user **walks away from has no event**: nothing on the server marks that moment (the
  session just expires, and expiry is not observed on every session store).
- **No independent OpenID Foundation conformance run yet.** This implementation has not been run against the
  OpenID4VP/HAIP conformance suite; see `ROADMAP.md` Phase 4.

## 9. Try it: the sandbox demo

The fastest way to see the whole flow (both credential formats, cross-device QR and same-device, plus linking a
wallet to an existing account) is the sandbox relying party's walkthrough:
**[`helix-sandbox-rp/README.md`](../helix-sandbox-rp/README.md) § "EUDI Wallet (OpenID4VP) — experimental"**. It
uses a throwaway, dev-only test wallet CLI (`TestWalletCli`) and a one-shot seed script
(`e2e/wallet-demo/seed.sh`) — nothing in that walkthrough is suitable for production credentials or keys.
