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
`revocationChecking` → `HARD_FAIL` (see §7.2); `statusList.required` → `false`; `subject.strategy` →
`ADMINISTRATIVE_NUMBER`; `minimumLoa` → `http://eidas.europa.eu/LoA/high`. `WalletConfigValidator` rejects an
invalid combination with `400 {message, fieldErrors}` naming the field, same shape as every other admin write
(`AdminValidationAdvice`).

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
  mismatch) or an answer that is not valid HTTP is not transient: it fails closed. Even then, the verifier emits an audit entry (`WALLET_STATUS_CHECK_FAILED` /
  `UNAVAILABLE_ACCEPTED`) so the operator can see that a login proceeded without a revocation check.
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
- Concurrent logins share one download per URL; at most `helix.wallet.fetch.max-concurrent` fetches (revocation and
  status lists together) run at once. A URL that served something that is not a CRL, or a CRL over the size cap, is
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
| `helix.wallet.fetch.max-concurrent` | `16` | Most issuer-revocation and status-list fetches running at once; a fetch that gets no slot before its deadline times out |

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
- **mdoc interop: one third-party check, no certified source.** Besides the in-repo test wallet, the mdoc decoding
  path (StrictCbor, IssuerAuth COSE_Sign1 with its own `x5chain`, MSO, IssuerSignedItem digests) is checked against
  DeviceResponses produced by the EU Digital Identity Wallet reference implementation (Apache-2.0; see
  `helix-iam-server/src/test/resources/wallet/vectors/SOURCES.md`). Their DeviceAuth cannot be checked (their
  SessionTranscript is not published), so the DeviceAuthentication construction is still covered only by the
  OpenID4VP B.2.6.1 transcript vector and our own wallet. The ISO 18013-5 text was not read and its Annex D vectors are
  not reproduced (ISO copyright). One reference credential carries a 31-byte device-key coordinate (a leading zero
  octet dropped; RFC 9053 asks for the full length): a coordinate shorter than the curve's field is left-padded with
  zero octets and accepted, as the same point, still checked to be on the curve; a longer or empty one is refused. A Phase 4 run against real wallets and issuers remains the real
  interop test.
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
- **No independent OpenID Foundation conformance run yet.** This implementation has not been run against the
  OpenID4VP/HAIP conformance suite; see `ROADMAP.md` Phase 4.

## 9. Try it: the sandbox demo

The fastest way to see the whole flow (both credential formats, cross-device QR and same-device, plus linking a
wallet to an existing account) is the sandbox relying party's walkthrough:
**[`helix-sandbox-rp/README.md`](../helix-sandbox-rp/README.md) § "EUDI Wallet (OpenID4VP) — experimental"**. It
uses a throwaway, dev-only test wallet CLI (`TestWalletCli`) and a one-shot seed script
(`e2e/wallet-demo/seed.sh`) — nothing in that walkthrough is suitable for production credentials or keys.
