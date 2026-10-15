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
- **Every replica converges without a restart.** Each write (admin API, console, realm import) bumps the realm's
  row in `idp_config_version` in the same transaction. The replica that handled the write (or ran the import)
  reloads that realm at once; every replica polls the versions every
  `helix.federation.store.poll-interval-seconds` (default **10**, env `HELIX_FEDERATION_STORE_POLL_INTERVAL_SECONDS`;
  `0` turns polling off) and reloads the realms whose version moved. This is plain PostgreSQL, so it works on the
  `queue` (PostgreSQL-only) deployment as well as with Redis. A change therefore reaches every replica within one
  interval.
- Publication is **version-ordered**: a refresh labels what it publishes with the version it read before loading,
  and a set older than the one already published is dropped. Two concurrent writes can no longer leave the older
  set live.
- **After a database restore, restart every replica.** A replica only reloads a realm whose version went *up*. A
  restore to an earlier backup can lower `idp_config_version` below what the replicas already published, and they
  would keep serving the newer (now gone) connections until a later write passes the old number. A restart loads every
  realm from the restored database. A transport that reports no versions at all (a custom
  `IdentityProviderConfigSource`) disables convergence; the poller logs a `WARN` at startup when that is the case.

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
`revocationChecking` → `HARD_FAIL` (see §7.2); `dcql.trustedAuthorities` → on for `x509_hash` with
`direct_post.jwt` (the HAIP profile), off otherwise (see §11); `statusList.required` → `false`; `subject.strategy` →
`ADMINISTRATIVE_NUMBER`; `minimumLoa` → `http://eidas.europa.eu/LoA/high`; `dcApi.enabled` → `false` (the W3C
Digital Credentials API, §12). Instead of `trustAnchors`, or as well, `trustedLists.sources` names the realm's
trusted lists (§7.3). `WalletConfigValidator` rejects an
invalid combination with `400 {message, fieldErrors}` naming the field, same shape as every other admin write
(`AdminValidationAdvice`).

### 2.5 Data retention when a realm is deleted

`realm_wallet_pepper`, `verifier_signing_key` and the PostgreSQL `wallet_transaction` rows are realm-scoped and now
get removed when their realm is: a `realm_config_delete_wallet_secrets` trigger (Flyway V85, `AFTER DELETE ON
realm_config`) deletes all three the moment a `realm_config` row is deleted — not soft-deleted, not recoverable —
including any in-flight wallet transactions. This matters because the pepper is the HMAC key behind every
weak-tuple subject (§6.2) and the administrative-number subject (§6.1): a realm created again under the same id
used to silently **inherit** the previous realm's pepper and verifier access key (whatever was left behind), which
is exactly the collision the trigger removes — a re-created realm now starts with neither, same as a brand-new one.

The same trigger deletes the realm's trusted list sources (`trusted_list_source`, §7.3); their members
(`trusted_list_member`) and rollback high-water marks (`trusted_list_hwm`) go with them through their own foreign keys.

It is a trigger, not a foreign key, deliberately: all three tables are routinely written for a realm id that has
no `realm_config` row yet (verifier-key import/generate and wallet-connection creation live under `/admin/**`,
which is never gated on realm existence, and `JdbcWalletTransactionStore` is exercised the same way by its own
tests) — a real `ON DELETE CASCADE` foreign key would also be an insert constraint and would turn a working admin
flow or transaction write into a constraint violation the first time it hit such a realm. The trigger only acts on
an actual `realm_config` delete, in the same transaction as that delete (so the cleanup is all-or-nothing), and
never touches a row whose `realm_id` has no matching `realm_config` row.

Two things this does **not** cover, by design:

- There is still no admin realm-delete operation or endpoint in HelixIAM today; this is schema-level preparation
  for whichever path removes a `realm_config` row, operator SQL included.
- `federated_link` (the account-link row behind `POST /account/wallet/link`, §6) has no `realm_id` column — it is
  keyed by `idp_alias` + `external_subject` + `user_id` — so it cannot be cascaded by realm. Wallet links are
  removed when the linked **user** is deleted, independent of the realm; deleting a realm today does not delete its
  users either, so this is consistent with the rest of the realm-deletion story, not a gap specific to the wallet.

## 3. Transaction store: PostgreSQL or Redis

Each wallet login's in-flight state (nonce, decryption key, bound-browser hash, DCQL query, TTL) lives in a
`WalletTransactionStore`, chosen at boot (`FederationConfig.WalletTransactionStores`). Every choice except the
explicit development one is shared by all replicas, so a cross-device (QR) login whose wallet requests land on a
different pod from the one that started it still works. **No sticky sessions are needed.**

- **PostgreSQL** (`JdbcWalletTransactionStore`, table `wallet_transaction`, Flyway V79) whenever
  `helix.iam.session-store=queue`, and whenever neither the session nor the token store is Redis.
- **Redis** (`RedisWalletTransactionStore`) when `helix.iam.session-store=redis`, or when
  `helix.iam.token-store=redis` and the session store is not `queue`.
- **In process memory** (`InMemoryWalletTransactionStore`) only when you ask for it with
  `helix.wallet.transaction-store=memory` (env `HELIX_WALLET_TRANSACTION_STORE`). It works with **one replica only**
  and is meant for development and tests; outside the `dev` profile startup logs a `WARN`.

`helix.wallet.transaction-store` (`jdbc`, `redis` or `memory`) overrides the automatic choice. A server with neither
Redis nor a database that was not asked for `memory` refuses to start rather than fall back silently.

Both shared stores keep the same guarantees:

- **Atomic, single-use transitions.** Redis runs one Lua script per transition; PostgreSQL runs one conditional
  statement (`UPDATE … WHERE … AND status = ? AND expires_at > ? RETURNING …`), so exactly one of any number of
  racing claims, completions, code issues or redeems wins. The same contract suite, including the 20-thread races,
  runs against both.
- **Secrets at rest.** The request ids, the response id and the response code are looked up by their SHA-256 only;
  the response code is stored only as its hash. The request ids, the response id, the private decryption key and the
  verified identity are encrypted with `DB_ENCRYPTION` (`AttributeEncryption`, which fails closed). Outside `dev`,
  creating a transaction without `DB_ENCRYPTION` is refused.
- **Expiry.** An expired transaction reads as absent at once. Redis evicts it by TTL; PostgreSQL deletes expired rows
  every `helix.wallet.transaction-sweep-seconds` (default 60). Expiry is checked against the application clock, so
  keep the replicas' clocks in sync (NTP), as you already must for token lifetimes.

## 4. Trusted proxies / allowed hosts

The wallet endpoints live under the same two settings as the rest of the server (README, "Client IP behind a reverse
proxy"):

- **`HELIX_TRUSTED_PROXIES`** (`helix.security.trusted-proxies`, comma-separated IPs or CIDR ranges, empty by
  default). The wallet's rate limits are per client IP: the `/oid4vp` group (the request object and the wallet's
  response, any method; `helix.ratelimit.wallet.*`, 120 a minute) and the `wallet-start` rule (a `GET
  /broker/<wallet alias>`, which creates a transaction; `helix.ratelimit.wallet-start.*`, 30 a minute). The client IP
  is the TCP peer unless that peer is a trusted proxy; only then is `X-Forwarded-For` read (from the right). A forged
  `X-Forwarded-For` from anyone else buys no new budget. Behind an ingress, list the ingress here, or every phone and
  browser shares the ingress's one budget.
- **`HELIX_ALLOWED_HOSTS`** (`helix.security.allowed-hosts`). Outside `dev` the server answers only for the hosts of
  `IDP_BASE_URL` and `SP_BASE_URL` plus this list; any other `Host` gets `400`. The wallet builds every URL it hands
  out — `client_id` (`x509_san_dns`), `response_uri`, the request URIs in the QR code and the "Open wallet" link — from
  `idp.base.url`, never from the request, so phones reach the IdP host, which is always allowed. A wallet sandbox or
  demo on another host name (not `localhost`) needs that host in `HELIX_ALLOWED_HOSTS`.

The limits match the still-encoded path, but no re-spelled path reaches the wallet code: the firewall refuses `%`,
`;`, `//` and `/./` (400), which `WalletLimitPathEncodingE2eTest` guards (see `DEFERRED-SECURITY-WORK.md`).

## 5. Status-list host allow-listing and SSRF

Every status-list fetch goes through `OutboundUrlGuard` — a `status_list.uri` must be `https`, must not resolve to
loopback/private/link-local/metadata addresses, and (optionally) must match `statusList.allowedHosts` if you set
it. This is the same egress guard every other admin-configurable outbound HTTP call in HelixIAM uses. The fetch
itself (and every redirect hop, at most 3, each vetted again) runs over a pinned connection: the host is resolved
once, inside the 5 s deadline, and the connection goes to the address the guard checked, so a resolver that answers
differently a second time (DNS rebinding) cannot redirect it; TLS is still verified against the host name. Connect
3 s, everything (DNS included) 5 s, body at most 1 MB. A provider's own https rule and `statusList.allowedHosts` are
applied before the (shared) status-list cache is consulted. A TLS failure (untrusted certificate, host name
mismatch) or an answer that is not valid HTTP fails closed, like any other integrity failure (see §7). See `helix-iam-server/SECURITY-REVIEW.md` Appendix B.5 for
the detail.

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
- **"Wallet linked" notice.** Because neither limit can be closed in the protocol, the user is told: whenever a
  wallet is linked to an account (the account console's "Link wallet" flow, or a sign-in that adds the
  administrative-number link to an account found by the tuple), the account's email address gets "An EU Digital
  Identity Wallet was linked to your account. If this wasn't you, unlink it and change your password." It goes
  through the realm's email provider and the `wallet-linked-notice` message template (English and Dutch defaults;
  reword it in the console under Messaging → Templates). It carries the realm name only: never the wallet subject or
  its hash, never a PID value. No email address on file, or no email provider configured, means no notice (the
  latter is logged as a warning). An existing link, or a wallet another account owns, sends none.

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
  availability problems: a connect or read error, a timeout (DNS included), a 5xx, a host name that does not
  resolve, or a thread interruption during the fetch. A TLS failure (untrusted server certificate, host name
  mismatch) or an answer that is not valid HTTP is not transient: it fails closed. Even then, the verifier emits an
  audit entry (`WALLET_STATUS_CHECK_FAILED` / `UNAVAILABLE_ACCEPTED`, naming the wallet `transactionId` of the login
  it let through) so the operator can see that a login proceeded without a revocation check.
- The **default** is `onUnavailable=FAIL_CLOSED` (so an unreachable status list blocks sign-in by default);
  `statusList.required=false` (so a PID that carries no `status` claim at all is still accepted — most short-lived
  PIDs do not bother with one).

- Verified status lists are cached (for `min(ttl, statusList.maxCacheSeconds)`, never past `exp`) in one cache
  shared by every wallet provider, bounded by entry count and by total decoded list bytes, least recently used
  evicted first:

  | Setting | Default | Meaning |
  |---|---|---|
  | `helix.wallet.status-list.cache-max-entries` | `64` | Most cached status lists |
  | `helix.wallet.status-list.cache-max-bytes` | `33554432` (32 MB) | Most decoded (inflated) list bytes held; a list larger than this is not cached |

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

### 7.2 Issuer certificate revocation (CRL / OCSP): `revocationChecking`

Separate from the credential's status list, the issuer's own X.509 signing certificate (and any intermediate below
the trust anchor) is checked for revocation, per provider (`revocationChecking`, console: *Credentials → Issuer
certificate revocation*):

| Mode | A certificate whose status cannot be determined | A revoked certificate |
|---|---|---|
| `HARD_FAIL` (**default**) | refused (`ISSUER_UNTRUSTED`, "certificate revocation status unavailable", or "revocation endpoint not allowed" when every source it names is refused by policy) | refused |
| `SOFT_FAIL` | accepted, with a warning naming its serial and subject DN | refused |
| `OFF` | not checked, nothing fetched | not checked |

How it works (`IssuerRevocationClient`):
- Nothing is fetched until the chain validates to one of your trust anchors.
- Each certificate is checked on its own, against its own issuer: OCSP first (POST), then the CRL distribution
  points; at most 2 URLs of each kind per certificate. A certificate that is revoked is refused even when another
  certificate in the path is undeterminable.
- Every URL passes `OutboundUrlGuard`; only `http` and `https` (CRL and OCSP are commonly plain `http`; their
  signatures are their integrity), never `ldap:`. The connection goes to the address the guard validated (no DNS
  rebinding), redirects are not followed, connect 3 s, 5 s per fetch in total including DNS, 10 s per chain.
- Concurrent logins share one download per URL; at most `helix.outbound.fetch.wallet.max-concurrent` wallet fetches
  (revocation and status lists together) run at once, in slots of their own: other outbound features (logins through
  OIDC/eID brokers, OTP delivery, webhooks/SCIM/logout) have separate groups and cannot take them. A URL that served something that is not a CRL, or a CRL over the size cap, is
  not downloaded again for 60 s.
- What was fetched is validated by the JDK (OCSP: `PKIXRevocationChecker` with the response supplied; CRL: the
  JDK's legacy CRL checker after HelixIAM's own pre-check). The JDK itself never fetches: HelixIAM sets
  `com.sun.security.enableCRLDP=false` at startup, and if a JVM setting would let the JDK fetch
  (`com.sun.security.enableCRLDP`, `com.sun.security.enableAIAcaIssuers`, `ocsp.enable`) or skip CA certificates
  (`com.sun.security.onlyCheckRevocationOfEECert`), CRLs are not evaluated (an error is logged) — do not set them.
- A CRL is accepted within the JDK's own 15-minute clock skew: `thisUpdate` up to 15 min in the future,
  `nextUpdate` up to 15 min in the past.
- Answers are cached until their `nextUpdate` (a CRL until `nextUpdate` + 15 min; at most 24 h; an OCSP response
  without `nextUpdate` is not cached), shared by every provider.

| Setting | Default | Meaning |
|---|---|---|
| `helix.wallet.revocation.max-crl-bytes` | `10485760` (10 MB) | Largest CRL downloaded (at most 100 MB); a larger one is an undeterminable status |
| `helix.wallet.revocation.cache-max-entries` | `256` | Most cached OCSP responses and CRLs |
| `helix.wallet.revocation.cache-max-bytes` | `33554432` (32 MB) | Most cached bytes: an OCSP response counts its size, a CRL an estimate of its parsed heap (3 × its size + 256 bytes per revoked entry) |
| `helix.outbound.fetch.wallet.max-concurrent` (old name `helix.wallet.fetch.max-concurrent` still read) | `16` | Most issuer-revocation and status-list fetches running at once; a fetch that gets no slot before its deadline times out. The other groups (`login-admin`, `login-client`, `otp`, `outbound`) have their own `helix.outbound.fetch.<group>.max-concurrent` (32) and `.per-realm-max` (8) |

OCSP responses are capped at 64 KB (not configurable).

**Latency.** With every endpoint slow or unreachable, one credential can take about 25 s to verify: up to 10 s for
the issuer chain's revocation checks, 5 s for the status-list fetch, and up to 10 s for the revocation checks of the
status-list signer's chain. Cached answers (CRLs and OCSP until `nextUpdate`, status lists for their `ttl`) make the
usual case fast; the wallet transaction lifetime (`transactionTtlSeconds`, default 300 s) is far longer.

**Why `HARD_FAIL` is the default.** Issuer-key revocation is the remedy for a compromised PID issuer key; under
`SOFT_FAIL` anyone who can make the issuer's CRL or OCSP endpoint unreachable from your server (or an issuer outage)
turns that remedy off, and credentials signed with the revoked key are accepted. PID document-signer certificates
carry a CRL distribution point (the EU reference implementation's `PID DS` certificates do), CRLs are valid for
hours to days, and the answers are cached until `nextUpdate`, so a short endpoint outage does not block logins.
This is the same choice as the status list's `onUnavailable=FAIL_CLOSED` default. Choose `SOFT_FAIL` for an issuer
whose certificates name no CRL or OCSP endpoint (they are refused under `HARD_FAIL`) or whose endpoints you cannot
reach; `OFF` only for testing. Providers stored before this change without a `revocationChecking` value now run
`HARD_FAIL` (see `CHANGES-1.0.md`).

### 7.3 Trust anchors from trusted lists

Instead of (or as well as) pasting PEM anchors, a wallet provider can take its PID issuer anchors from **published,
signed trusted lists** that HelixIAM fetches, verifies and refreshes itself (`TrustedListService`,
`helix-iam-server/src/main/java/io/helixiam/authorization/federation/wallet/trust/tl/`). Console: **Federation →
Trusted lists**; admin API: `/admin/realms/{realm}/trusted-lists`.

**What is published (checked 15 October 2026).**

| Source | Format | What it lists | Status |
|---|---|---|---|
| EUDI Wallet reference implementation, `https://trustedlist.serviceproviders.eudiw.dev/LOTL/01.xml` | ETSI TS 119 612 v2 XML, a list of trusted lists (16 test lists), XAdES enveloped (ECDSA) | PID providers (`http://uri.etsi.org/Svc/Svctype/Provider/PID`), wallet providers, access-certificate CAs, (Q)EAA, with status `recognisedatnationallevel` | **Test only.** Its signer certificate expired on 4 July 2026 (it was valid when the current list was issued); NextUpdate 27 October 2026 |
| European Commission, `https://acceptance.trust.tech.ec.europa.eu/lists/eudiw/pid-providers.json` | ETSI TS 119 602 V1.1.1 List of Trusted Entities, JSON in a JWS compact serialization (JAdES, RS512, `x5c`) | PID providers (`http://uri.etsi.org/19602/SvcType/PID/Issuance` and `/Revocation`) | **Acceptance environment.** The production path (`trust.tech.ec.europa.eu/lists/eudiw/…`) answers 404: no production list of PID providers is published yet |
| EU list of trusted lists, `https://ec.europa.eu/tools/lotl/eu-lotl.xml` | ETSI TS 119 612 v2 XML (TSL version 6), XAdES (RSA-SHA512), pointing at ~30 national lists | Qualified trust services under eIDAS (CA/QC, QTST, …) | Production, but it does **not** list PID providers |

HelixIAM reads both formats: **ETSI TS 119 612 XML** (a trusted list, or a list of trusted lists whose pointers are
followed one level) and **ETSI TS 119 602 LoTE JSON**. Nothing is specific to one publisher: the URL, the pinned
signer certificates, the service types and the accepted statuses are configuration, so a list published later in
either format works without code changes. All three lists above were fetched and verified with this code
(`PublishedTrustedListsManualTest`, opt-in with `-Dhelix.tl.live=true`; never run in CI).

**A source** (per realm) has: a name, the https URL, the format, the **pinned signer certificates** (PEM), the
service types to extract, the statuses that count (default `granted` and `recognisedatnationallevel`; `withdrawn` and
`deprecatedatnationallevel` can never be chosen), for a list of lists optionally the territories whose lists are read
(`NL`, `DE`, …), and a **grace period** (hours, default 24, at most 720).

**A provider** names sources in `trustedLists.sources` (a JSON array of source names) and may narrow them with
`trustedLists.serviceTypes`. `trustAnchors` (pasted PEM) is then optional; both may be set and are combined. The
anchors are read at every verification, so a refresh, a withdrawal or an expiry takes effect at once.
`IssuerTrustValidator` is unchanged: it gets one `TrustAnchors` as before.

```json
"config": {
  "accessKeyRef": "software:gov/primary",
  "trustedLists.sources": "[\"eudi-pid-providers\"]",
  "trustedLists.serviceTypes": "[\"http://uri.etsi.org/19602/SvcType/PID/Issuance\"]"
}
```

**Verification.** A list counts only when:

- it was fetched over https through the pinned transport (`OutboundUrlGuard` checks the host, the connection goes
  to the checked address, the certificate is verified against the host name, no redirect is followed: configure the
  final URL; at most `helix.wallet.trusted-lists.max-bytes`, 16 MB; connect 5 s, 30 s in total; slots of the
  `WALLET` fetch-limiter group, per realm);
- its signature verifies with **one of the pinned signer certificates** (never with the certificate the list carries
  in its own `KeyInfo` or `x5c`). That certificate must have an RSA (≥ 2048 bits) or EC (P-256 or stronger) key and
  must have been valid at the list's `ListIssueDateTime`. It must also not have expired, whatever date the list
  claims, beyond a grace that differs by who vouches for the signer (ETSI TS 119 615):
  - an **admin-pinned signer of a top-level list** (a trusted list, or a list of trusted lists): grace
    `helix.wallet.trusted-lists.signer-expiry-grace-days`, **default 0**. PRO-4.1.4-07/08 make an expired signer
    without proof of existence INDETERMINATE, which stops validation; the console then says the pinned signer has
    expired. Lists are signed at issue and stay valid until NextUpdate, so a test publisher's signer can lapse first:
    as of 2026-10-15 the EUDI reference implementation's test LOTL (issued 2026-04-30, signer expired 2026-07-04)
    loads only with `signer-expiry-grace-days` ≥ about **120**, and the Commission's acceptance LoTE (signer expired
    2026-09-15) with ≥ about **30**. Set it deliberately for such test lists; there is no lenient default, also not
    in `dev`;
  - a **member list's signer named by the verified list of lists**: grace
    `helix.wallet.trusted-lists.member-signer-expiry-grace-days`, **default 180 days** (PRO-4.2.4-09: a member TL
    stops only on "failed"), still bounded by the signer being valid at the member's issue time and by the
    six-month NextUpdate cap below.

  XML: exactly one enveloped `ds:Signature` under the root, one reference covering the whole list
  (`URI=""` or the root's `Id`), only same-document references, only enveloped-signature and canonicalization
  transforms, unique `Id` attributes; signature RSA PKCS#1 v1.5, RSASSA-PSS with MGF1 (the fixed-hash
  `sha*-rsa-MGF1` identifiers only; the parameterised `rsa-pss` identifier is refused) or ECDSA with SHA-256/384/512,
  and reference digests SHA-256/384/512 only (checked by HelixIAM: Santuario's secure validation alone still accepts
  SHA-1 digests). JSON: RS/PS/ES 256/384/512, no `alg=none`, no detached or unencoded payload;
- it was parsed without a DOCTYPE (so no entities), without XInclude or external DTD/schema access, at most 64
  levels deep;
- its `NextUpdate` has not passed (a list without one is a closed list and is refused), counting it at most until
  `ListIssueDateTime` plus six months (ETSI TS 119 612 §5.3.14; `helix.wallet.trusted-lists.max-validity-months`),
  and its sequence number is not lower than that of the last list accepted (rollback; also enforced in SQL);
- for a list of trusted lists: each XML pointer to a non-list-of-lists list in the chosen territories is a
  **member**, judged on its own: it must be https, verify with the signer certificates **the list of lists names for
  it**, carry the `SchemeTerritory` and `TSLType` the pointer names, be fresh, and not have a lower sequence number
  than the **high-water mark** of its territory and TSLType: the highest sequence number accepted for them, kept
  per source even when the member's URL changes or the list of lists stops pointing at it for a while (enforced in
  the loader and in SQL, MACed like the anchors). A member that fails (a plain-http pointer is skipped and reported the same
  way) keeps its own last good anchors until its own NextUpdate plus grace, then gives none; the other members are
  not affected. Members the list no longer points at are dropped. PDF renditions and pointers to other lists of
  lists are skipped.

From a verified list HelixIAM keeps every service of the configured types whose **current** status is accepted and
started (service history is ignored; in a LoTE, a service without a status counts, as listing is the trust decision
there, and one with a status counts only when it is accepted), and stores the services; only **CA certificates** that pass the usual anchor
rule (EC P-256/384/521 or RSA ≥ 2048, `keyCertSign`) become anchors. A listed end-entity certificate is shown in the
preview as "not a CA" and not used.

**Refresh and fail-safe.** Each replica checks every `helix.wallet.trusted-lists.check-interval-seconds` (60) for
sources that are due; the one that takes the row's lease (a conditional update on `trusted_list_source`) refreshes,
the others wait. The lease is renewed while a load runs, is not re-entrant (the console and the scheduler of one
replica cannot refresh the same source together), and is cleared by a settings change: a refresh stores its result
only if it still holds the lease and the settings it started with are unchanged, otherwise the result is dropped and
audited as `TRUSTED_LIST_REFRESH_DISCARDED`. A healthy source is refreshed at the earlier of its NextUpdate and
`helix.wallet.trusted-lists.refresh-interval-minutes` (360) after the last refresh; a failed one after
`retry-interval-minutes` (15). **Refresh now** in the console does the same at once (`409` while another refresh
holds the lease). The verified services are stored in the database; every replica reloads the sources whose version
moved every `poll-interval-seconds` (10).

| Status | Anchors used | When |
|---|---|---|
| `OK` | yes | The last refresh verified a list whose NextUpdate has not passed |
| `FAILING` | yes (last good) | The last refresh failed (unreachable, bad signature, rollback, …) but the last good list is before its NextUpdate |
| `STALE` | yes (last good) | Past the last good list's NextUpdate, within the grace period |
| `EXPIRED` | **no** | Past NextUpdate plus grace: fail closed until a new list verifies |
| `DEGRADED` | yes (the good members) | A list of trusted lists that is itself fine, with some members failing, stale, expired or never verified; each member has its own status |
| `NEVER` / `ERROR` | no | Never loaded / never verified (console: "Never verified") |
| `INTEGRITY` | **no** | The stored settings or anchors failed their integrity check (see below) |
| `DISABLED` | no | Switched off |

Changing what a source loads (URL, format, signers, types, statuses, territories) drops its stored anchors at once.
Providers name a source, so **renaming or deleting a source that providers use is refused** (`409`; remove it from
them first) rather than silently re-pointing or orphaning them. Every update must send the `configVersion` of the
source it edited: when another admin saved in between, the update is a `409` (the console says the list was changed
by someone else and offers to reload) instead of overwriting their change.

**Integrity of the stored rows.** HMAC-SHA256, keyed from `DB_ENCRYPTION`, covers every stored value that decides
trust: a source's settings (realm, name, URL, format, pinned signers, service types, accepted statuses, territories,
grace hours, the switch and its `configVersion`), the stored services of the source and of each member (with their
sequence number and NextUpdate, bound to the `configVersion` they were loaded under), and the rollback high-water
marks. `grace_hours` is also clamped to 0-720 when read. What happens when a check fails:

- **Settings fail**: the MAC is wrong or missing (modified outside HelixIAM, stored before V84, or `DB_ENCRYPTION`
  changed). The source shows `INTEGRITY`, gives no anchors, `TRUSTED_LIST_INTEGRITY_FAILED` is audited, and every
  refresh fails with `INTEGRITY` (audited) until an admin checks the settings and saves them again. Settings are never
  adopted automatically.
- **Anchors, a member's anchors or high-water marks fail** (or have no MAC) while the settings verify: they give no
  anchors, and the **next refresh discards all loaded state and reloads it from the signed list** with full
  verification, rebuilding the high-water marks from that list; audited as `TRUSTED_LIST_INTEGRITY_RESET`, naming
  what failed.
- So after **changing `DB_ENCRYPTION`**: save each source again (new settings MAC), then refresh it (the anchors are
  reloaded).
- **Sources stored before V84** (no MACs; V81-V84 ship together, so only a database that ran this branch before its
  release can hold them) are integrity failures like any other: an admin saves each one again, then a refresh
  reloads its anchors.

Outside the `dev` profile a source cannot be saved without `DB_ENCRYPTION`; in `dev` without it there is no MAC and
nothing is checked.

An integrity reset drops anchors and member state but **keeps the rollback floors**: the top-level sequence number
and every high-water mark stay, whatever their MACs, and a floor is only ever raised, by a verified load (which
re-MACs it under the current key). So changing `DB_ENCRYPTION` never lets an older signed list back in. A member row
below its floor is not counted (audited).

**Scope.** These MACs are best-effort tamper detection, not a defence against someone who can write the database:
HelixIAM does not defend against that anywhere else either (a wallet provider's pasted `trustAnchors` PEM is plain
configuration). The high-water marks stop **network** rollback (a man in the middle, or a stale mirror serving an
older signed list); a database writer who deletes high-water-mark rows can re-open rollback, which is out of scope.

**Audit and logs.** `TRUSTED_LIST_REFRESHED` (services, usable anchors, lists verified, sequence, NextUpdate, members
loaded and failed), `TRUSTED_LIST_REFRESH_FAILED` (reason, message, status, until when the last good anchors are kept),
`TRUSTED_LIST_REFRESH_DISCARDED`, `TRUSTED_LIST_MEMBER_REFRESH_FAILED` (per member), `TRUSTED_LIST_STALE`,
`TRUSTED_LIST_EXPIRED`, `TRUSTED_LIST_MEMBER_STALE` and `TRUSTED_LIST_MEMBER_EXPIRED` (each once, on one replica),
`TRUSTED_LIST_SIGNER_EXPIRING` / `_EXPIRED` (a pinned signer expiring within 30 days, at every refresh) and
`TRUSTED_LIST_INTEGRITY_FAILED`, all ADMIN-category with actor `system`; the admin writes are
`TRUSTED_LIST_CREATE|UPDATE|DELETE|REFRESH_REQUEST`, with the name, URL and SHA-256 fingerprints of the pinned
signers (and the previous values on an update). Each is also logged (refresh INFO,
failure and stale WARN, expiry ERROR).

**Pinning the signer.** The signer certificates must come from the publisher through a channel you trust, never from
the list itself (the console's presets fill in the URL, format and service types, never a signer). For the EU list of
trusted lists that is the Official Journal publication of the LOTL signing certificates. When a publisher rotates its
signing key, the list stops verifying: the source goes `FAILING`, then `STALE`, then `EXPIRED`; update the pinned
certificates before the grace period ends. Automatic signer rotation (the LOTL "pivot" mechanism) is not implemented
(see `DEFERRED-SECURITY-WORK.md`).

| Setting | Default | Meaning |
|---|---|---|
| `helix.wallet.trusted-lists.refresh-interval-minutes` | `360` | Longest time between refreshes of a healthy source |
| `helix.wallet.trusted-lists.retry-interval-minutes` | `15` | Wait after a failed refresh |
| `helix.wallet.trusted-lists.check-interval-seconds` | `60` | How often each replica looks for due sources (`0`: only "Refresh now") |
| `helix.wallet.trusted-lists.poll-interval-seconds` | `10` | How often each replica reloads sources that changed elsewhere |
| `helix.wallet.trusted-lists.max-bytes` | `16777216` (16 MB) | Largest list fetched |
| `helix.wallet.trusted-lists.signer-expiry-grace-days` | `0` | How long after its expiry an admin-pinned signer of a top-level list may still verify a list issued while it was valid (ETSI TS 119 615 PRO-4.1.4; the EUDI test LOTL needs ≥ ~120) |
| `helix.wallet.trusted-lists.member-signer-expiry-grace-days` | `180` | The same for a member list's signer named by the verified list of lists (PRO-4.2.4-09) |
| `helix.wallet.trusted-lists.max-validity-months` | `6` | A list counts at most this long after its issue time, whatever its NextUpdate says |

Not exported or imported with a realm: a realm import whose wallet provider names a trusted list fails validation
until the source exists in the target realm.

## 8. Limitations

- **Three ways to reach the wallet.** Same-device redirect (`haip-vp://`, "Open wallet app"), cross-device QR
  (`request_uri` + `direct_post.jwt`), and, when a connection turns it on, the **W3C Digital Credentials API**
  (`dc_api.jwt`, §12), which the browser offers for a wallet on the same device or a phone nearby. The DC API is opt-in
  per connection and appears only in browsers that support it; the other two stay as the fallback. It has not yet been
  run against a real wallet (§12.6).
- **Cross-device QR vs ARF guidance.** The spec this feature was built against requires cross-device QR support;
  separate EUDI ARF guidance (OIA_08c) recommends that conformant EU wallets *not* support redirect-based
  cross-device flows at all, and points to the Digital Credentials API instead (§12). The EU reference wallet
  (2026.10.43-Demo) does accept HelixIAM's cross-device request (§10); whether national wallets will is still open.
- **Trusted lists: what is not automated.** Trust anchors can come from signed trusted lists (§7.3), but the lists'
  own signer certificates are pinned by hand (no LOTL pivot / signer rotation), LoTE pointers to other LoTEs are not
  followed, and no production EU list of PID providers is published yet (only the EUDI test list and the
  Commission's acceptance list).
- **`deviceMac` is rejected outright** (`HOLDER_BINDING_INVALID`,
  `MdocPresentationVerifier.java:469-470`) — only `deviceSignature` (asymmetric holder binding) is accepted for
  mdoc. This is deliberate: MAC-based device authentication needs a reader key the redirect-based flow here has
  no way to establish (the spec notes call out why in their mdoc section), not an oversight.
- **mdoc and SD-JWT VC interop: checked against the EU reference wallet, no certified source.** Besides the in-repo
  test wallet, presentations the EU Digital Identity Wallet reference app posted to this verifier on 2026-10-15 are
  kept with their request objects and decryption keys and are verified offline on every build, mdoc DeviceAuth over
  the real SessionTranscript included (§10). The mdoc decoding path is also checked against DeviceResponses published
  in the EU reference verifier's tests (Apache-2.0; their DeviceAuth cannot be checked, their SessionTranscript is not
  published). See `helix-iam-server/src/test/resources/wallet/vectors/SOURCES.md`. The ISO 18013-5 text was not read
  and its Annex D vectors are not reproduced (ISO copyright). One published reference credential carries a 31-byte
  device-key coordinate (a leading zero octet dropped; RFC 9053 asks for the full length): a coordinate shorter than
  the curve's field is left-padded with zero octets and accepted, as the same point, still checked to be on the curve;
  a longer or empty one is refused. No national wallet has been tested yet.
- **Several realms in one browser.** The broker keeps its per-login state (state, browser binding, wallet
  transaction) per realm and alias, so logins in two realms that use the same alias (the console's default
  `eudi-wallet`) can run side by side in one browser.
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
- **Request objects: re-fetch until the response, one flow only.** The first fetch of a `request_uri` binds the
  login to that flow (same-device or cross-device); the other invocation is `404` from then on. The same `request_uri`
  can be fetched again, and returns the same request, until the wallet has posted its response; after
  that, or once the login ended or expired, it is `404`. The response itself is single use.

## 9. Try it: the sandbox demo

The fastest way to see the whole flow (both credential formats, cross-device QR and same-device, plus linking a
wallet to an existing account) is the sandbox relying party's walkthrough:
**[`helix-sandbox-rp/README.md`](../helix-sandbox-rp/README.md) § "EUDI Wallet (OpenID4VP) — experimental"**. It
uses a throwaway, dev-only test wallet CLI (`TestWalletCli`) and a one-shot seed script
(`e2e/wallet-demo/seed.sh`) — nothing in that walkthrough is suitable for production credentials or keys.

## 10. Interop: the EU reference wallet

Tested on 2026-10-15 against the EU Digital Identity Wallet reference app for Android (`eudi-app-android-wallet-ui`
2026.10.43-Demo, released APK, `demo` flavour) on an Android 15 emulator, with PIDs from the EU reference test issuer
(`issuer.eudiw.dev`). Full record, versions, steps and screenshots: `docs/compliance/eudi-reference-wallet/README.md`.

| Flow | SD-JWT VC PID | mdoc PID |
|---|---|---|
| Same-device | Pass | Pass |
| Cross-device (QR) | Pass (QR content handed to the wallet by an Android intent, not the camera) | Pass (same) |

Every run used the defaults: `client_id` prefix `x509_hash`, invocation scheme `haip-vp://`, `direct_post.jwt`,
issuer-certificate revocation `HARD_FAIL` and status list `FAIL_CLOSED`. No HelixIAM change was needed. What you need to
know to repeat it:

- **The wallet only talks to verifiers on the EU trusted list.** Its released builds check the request object's `x5c`
  against the reference implementation's `WRPACProviders` list and have no switch to turn that off, so (per the app's
  source; we did not try it) a self-made certificate is refused. The EU's **Testing Relying Party Registration** service
  (`https://registry.serviceproviders.eudiw.dev`) issues test access certificates under that list; you authenticate to
  it by presenting a test PID from the same wallet. Import the certificate's key and chain as the verifier key (§2.4).
- **`x509_san_dns` needs a dNSName** in the access certificate. The test registrar's certificates have none, so use
  `x509_hash` (the default) with them.
- **Trust anchors:** the PID issuer CAs are in the reference implementation's `PIDProviders` list (the test issuer
  signs with `PID Issuer CA - UT 02`).
- **TLS:** the wallet trusts the device's system CAs only.
- **Declining sends nothing.** When the user taps Cancel, the reference wallet posts no error response, so the
  browser page waits until the transaction expires (`transactionTtlSeconds`).
- **The captures are test vectors.** Four of the presentations (both formats, both flows) with their request objects
  and the verifier's per-transaction decryption keys are in `helix-iam-server/src/test/resources/wallet/vectors/
  eudi-reference-wallet/`; `EudiReferenceWalletCaptureVectorTest` verifies them offline with the production code,
  including mdoc DeviceAuth over the real OpenID4VP SessionTranscript and the SD-JWT VC Key Binding JWT.

## 11. OpenID Foundation conformance run

The verifier was run against the OpenID Foundation conformance suite (version 5.3.3, revision `f0133e9`), with the
suite playing the wallet, on 2026-10-15, covering:
- the HAIP certification plan (`oid4vp-1final-verifier-haip-test-plan`) and the plain OpenID4VP 1.0 plan
  (`oid4vp-1final-verifier-test-plan`);
- `dc+sd-jwt` and `mso_mdoc`;
- `x509_hash` and `x509_san_dns`;
- `direct_post.jwt` (and `direct_post` in `dev`);
- `request_uri` with GET and POST;
- same-device and cross-device.

This is a self-run of the open-source suite, not an OpenID Certification. Every positive test ended in a sign-in, and
every negative test was refused by the check it targets.

The first run reported three findings:
- **`request-uri-fetched-twice` failed** because request objects were single use. **Fixed:** the same `request_uri` can
  now be fetched again until the response (§8), and the re-run passes it in every plan.
- **A nonce-entropy warning** on the happy flows. It comes from a suite heuristic that flags most 128-bit base64url
  nonces, so it is not changed; an issue for the suite is drafted.
- **The HAIP cross-device happy flow** fails the "`redirect_uri` in the response to the wallet's POST" check. HAIP §5.1
  requires that only for same-device logins, so it is not changed.

The suite does not test HAIP §5's DCQL `trusted_authorities`, but HAIP requires verifiers to support it, so it was
added after the run:
- **What is sent.** Each PID Credential Query carries `{"type": "aki", "values": [...]}`. The values are the key
  identifiers of the trust anchors and pinned intermediates, the AuthorityKeyIdentifier of the certificates they issue.
  With trusted lists (§7.3), the values follow the lists' current anchors at each request.
- **Default.** Per provider, `dcql.trustedAuthorities` (console: Credentials → "Name the trusted issuers in the
  request"). Unset means on for the HAIP profile (`x509_hash` with `direct_post.jwt`) and off otherwise.
- **Enforcement.** It only tells the wallet which issuers to offer; validating the chain to `trustAnchors` still
  decides.
- **Anchors without a SubjectKeyIdentifier.** The values are never guessed. If any trust anchor (or pinned
  intermediate) has no SubjectKeyIdentifier extension, `trusted_authorities` is left out of the query and the server
  logs one WARN when it loads the provider. Saving a provider with the setting explicitly **On** and such an anchor is
  refused (`400`, field `dcql.trustedAuthorities`, naming the anchor).
- **Escape hatch.** If a wallet answers with no credential (it filters on `trusted_authorities` and finds no match),
  set the provider to **Off**. Nothing else changes, because the trust decision never depended on the query.

The results per plan and module, the root cause of each finding, the logs of both runs and the harness to repeat them
are in **[`docs/compliance/oid4vp-conformance/README.md`](compliance/oid4vp-conformance/README.md)** (harness:
`e2e/oid4vp-conformance/`).

## 12. The W3C Digital Credentials API (`dc_api` / `dc_api.jwt`)

OpenID4VP 1.0 Appendix A defines how a verifier's web page asks for a credential through the browser itself:
`navigator.credentials.get({digital: {requests: [{protocol, data}]}})`. The browser and the operating system show the
user which wallets can answer and who is asking (the page's origin, which the browser vouches for), and hand the
answer back to the same page. Cross-device works through the platform (a phone nearby, via the FIDO hybrid
transport), with proximity checked by the platform rather than by a QR code anyone can relay. HAIP 1.0 §5.2 makes it
the HAIP way to present over the web, with `dc_api.jwt`. Design record:
`docs/superpowers/specs/2026-10-15-wallet-dc-api-design.md`.

### 12.1 Turning it on

Per connection, off by default:

| Setting (stored key) | Default | Meaning |
|---|---|---|
| `dcApi.enabled` | `false` | Offer the DC API on the wallet page. |
| `dcApi.request` | `signed` | `signed` (`openid4vp-v1-signed`: a JWS by the access certificate, `client_id` = `x509_hash:` or `x509_san_dns:`, with `expected_origins`) or `unsigned` (`openid4vp-v1-unsigned`: plain parameters, no `client_id`). |
| `dcApi.expectedOrigins` | empty | JSON list of the web origins the page is served on; empty means the origin of `IDP_BASE_URL`. |

Console: the connection's **Policies** tab (or the wizard's Policies step) → **Digital Credentials API**: a switch,
Signed/Unsigned, and the expected origins (one per line). Unsigned shows a warning: the wallet can then only check the
browser-reported origin, not the access certificate. Prefer signed.

The response is encrypted (`dc_api.jwt`, ECDH-ES P-256, `A128GCM`/`A256GCM`, to the transaction's own ephemeral key,
the same as for `direct_post.jwt`) whenever `responseMode` is `direct_post.jwt`. With the dev-only `direct_post` it is
`dc_api` (plain).

### 12.2 Origins: from configuration, never from the request

The response is accepted only if it is bound to one of the **expected origins**, and that list comes only from
configuration:
- `dcApi.expectedOrigins`, or else the origin of `IDP_BASE_URL` (lower-case scheme and host, no default port).
- Each configured origin must be written exactly as a browser serialises it (`https://login.example.eu`,
  `https://login.example.eu:8443`; no path, no trailing slash, no `:443`), at most 10, and on a host this server
  answers for: the host of `IDP_BASE_URL` or one listed in `HELIX_ALLOWED_HOSTS` (§4). Plain `http` only for
  `localhost` in `dev`.
- The page's `Origin` header, its URL and anything in the wallet's answer are never used to pick it.

What "bound" means (OpenID4VP A.4, B.2.6.2):
- SD-JWT VC: the Key Binding JWT `aud` is `origin:<expected origin>` (never the `client_id`, even for signed
  requests). Otherwise `AUDIENCE_MISMATCH`.
- mdoc: DeviceAuth verifies over the SessionTranscript `[null, null, ["OpenID4VPDCAPIHandover",
  sha256(cbor([origin, nonce, jwkThumbprint]))]]` of an expected origin (`jwkThumbprint` is `null` for `dc_api`).
  Otherwise `HOLDER_BINDING_INVALID`. The transcript code matches the spec's example byte for byte.
- A signed request also lists the expected origins in `expected_origins`, so the wallet itself refuses a request
  replayed by another site. For an unsigned request the wallet cannot do that, but its answer is then bound to the
  other site's origin and refused here.
- A presentation made for the redirect flows (bound to `client_id` / the `OpenID4VPHandover`) is refused over the
  DC API, and a DC API presentation is refused at the redirect `response_uri`.
- **The expected origins are interchangeable.** A response bound to *any* origin in the list is accepted, whichever of
  them the login page was actually served on: the transaction does not record its page's origin. They are all hosts of
  this server, so this keeps every foreign origin out. It matters once one server serves several tenants under their
  own domains; per-organisation custom domains are deferred, and with them per-host binding
  (`helix-iam-server/DEFERRED-SECURITY-WORK.md`). Until then, list only origins that belong to the same deployment.

### 12.3 The flow

1. The wallet page (`/realms/<realm>/broker/<alias>/wallet?tx=…`) loads `/js/wallet-dcapi.js`. It shows **Continue
   with your wallet** only if the browser has `DigitalCredential` and `navigator.credentials.get`, and (where the
   browser can say) `DigitalCredential.userAgentAllowsProtocol(<protocol>)`. Otherwise nothing changes on the page.
2. On click, the page POSTs `…/wallet/dc-api/request?tx=…` and gets `{"protocol": …, "data": …}`. No `response_uri`,
   no `state`, no `request_uri`. This does not change the transaction: if the user closes the browser's wallet
   chooser, the QR code and "Open wallet app" still work.
3. The page calls `navigator.credentials.get` with it and POSTs the returned `DigitalCredential` as
   `{"protocol", "data"}` to `…/wallet/dc-api/response?tx=…`.
4. The server verifies it. The answer is `200 {"status": "COMPLETED", "next": "<broker callback>?response_code=…"}`, or
   `{"status": "FAILED", "reason": "declined" | "not_accepted" | "expired" | "technical"}`. The page follows `next`,
   which redeems the code exactly as the cross-device flow does (code + session state + browser binding, single use).

### 12.4 Protections

- **Browser binding and CSRF.** Both endpoints sit under the wallet page: they need the session that started the login
  (its browser binding must match the transaction's, else `404`) and Spring Security's CSRF token (`X-XSRF-TOKEN`,
  rendered into the page; else `403`). They are not CSRF-exempt, unlike the wallet-facing `/oid4vp/**` endpoints.
- **Single use.** The response claims the transaction atomically (`WalletTransactionStore.claimDcApiResponse`:
  `CREATED` → `RESPONSE_RECEIVED`, flow `DC_API`; in-memory, PostgreSQL and Redis stores). A second post, or a post
  after a wallet already fetched the QR or same-device request, is refused (`REPLAY`). Conversely, once the DC API
  answer is in, the QR and same-device request ids are dead.
- **Wrong transaction.** A response made for another transaction carries that transaction's nonce and encryption key,
  so it cannot decrypt or verify; the transaction it was posted to fails.
- **Body.** `application/json`, strict JSON (duplicate members refused), exactly `protocol` and `data`, `protocol` equal
  to the one offered, `data` with exactly one of `response` / `vp_token` / `error`; at most
  `helix.wallet.max-request-bytes` (256 KiB), else `413`.
- **Audit.** Refusals on this path are `WALLET_LOGIN_FAILURE` events with `invocation=dc_api` added to the detail; a
  successful login is the usual `WALLET_LOGIN_SUCCESS` when the code is redeemed (same `transactionId`). The server
  log shows `flow=DC_API`.

### 12.5 Not supported

Multi-signed requests (`openid4vp-v1-multisigned`), `transaction_data`, `verifier_info`, the ISO `org-iso-mdoc`
protocol (ISO 18013-7 Annex C), and native apps as callers.

### 12.6 Real-wallet status

Not yet run against a real wallet over the DC API. The automated coverage is: unit tests against the spec's
Appendix B.2.6.2 vector, and `WalletDcApiFlowE2eTest`, where the in-repo test wallet plays both the browser and the
wallet (`DcApiWalletClient` checks `expected_origins` against the origin as a wallet must). An attempt to repeat the
§10 emulator run over the DC API on 2026-10-15 stopped before it started, for these reasons:
- The Android 15 `google_apis` emulator image used for §10 ships Chrome 124. Chrome on Android shipped
  `navigator.credentials.get({digital: …})` later (Chrome 141); 124 has neither this shape nor the protocol
  identifiers. That image has no Play Store, so Chrome cannot be updated there except by sideloading Chrome and
  Trichrome APKs from an unofficial mirror, which this project does not do.
- The `google_apis_playstore` image could update Chrome and Google Play services (Credential Manager), but does not
  allow `adb root`, which the run needs to put the local TLS CA into the system store (§10 step 5).
- The verifier access certificate of the §10 run is not on the test machine any more, and the AVD and the wallet's
  test PIDs were deleted, so a new run also has to register again with the EU test registrar (§10 step 4).

A live check needs a physical Android phone with a current Chrome and the reference wallet (which, per the §10 notes,
supports the DC API), or an emulator image with Play Store plus a TLS certificate from a public CA for the verifier.
