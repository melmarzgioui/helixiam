# Vendor map: mfnr-subscriber-starter → helix-iam-server

Task 1 of the HelixIAM "strip RabbitMQ" migration vendored the non-AMQP infrastructure
classes of `mfnr-subscriber-starter` (source repo:
`kube-dna/components/mfnr-subscriber-starter/`) into `helix-iam-server` under `io.helixiam.*`,
with zero `group.mfnr.*` and zero AMQP/RabbitMQ references.

Task 2 (rewriting the business-logic modules' imports) should use the FQN table below.

## FQN mapping table

| Old FQN (group.mfnr.subscriber.starter.*) | New FQN (io.helixiam.*) | Notes |
|---|---|---|
| `config.StarterLoggingProperties` | `common.config.StarterLoggingProperties` | Trimmed: `amqpBridge`/`amqpFederate` fields dropped; `@ConfigurationProperties` prefix changed `mfnr.subscriber.starter.logging` → `helixiam.logging` |
| `utils.LanguageUtility` | `common.utils.LanguageUtility` | Verbatim |
| `database.DatabaseConstant` | `persistence.DatabaseConstant` | Verbatim |
| `database.aop.ReadOnlyDatasource` | `persistence.aop.ReadOnlyDatasource` | Verbatim |
| `database.aop.TransactionReadOnlyAspect` | `persistence.aop.TransactionReadOnlyAspect` | Verbatim |
| `database.config.DataSourceConfiguration` | `persistence.config.DataSourceConfiguration` | Verbatim (already had single-datasource fallback) |
| `database.config.DatabaseEnvironment` | `persistence.config.DatabaseEnvironment` | Verbatim |
| `database.config.ReadWriteRoutingDataSource` | `persistence.config.ReadWriteRoutingDataSource` | Verbatim |
| `database.context.DatabaseContextHolder` | `persistence.context.DatabaseContextHolder` | Verbatim |
| `database.exception.DatabaseException` | `persistence.exception.DatabaseException` | Now extends `io.helixiam.common.exception.ValidationException` (see below) |
| `database.exception.DatabaseExceptionHandler` | `persistence.exception.DatabaseExceptionHandler` | Now throws `io.helixiam.common.exception.DuplicateException` |
| `database.filter.FilterCriteria` | `persistence.filter.FilterCriteria` | Verbatim |
| `database.filter.FilterOperation` | `persistence.filter.FilterOperation` | Verbatim |
| `database.filter.FilterSpecification` | `persistence.filter.FilterSpecification` | Verbatim |
| `database.security.AttributeEncryption` | `persistence.security.AttributeEncryption` | Verbatim — AES/GCM (+legacy AES fallback) semantics preserved byte-for-byte |
| `notification.NotificationConstant` | `notification.NotificationConstant` | AMQP routing constants (`VIRTUALHOST_NOTIFICATION`, `EXCHANGE_NOTIFICATION`, `NOTIFICATION_*_ROUTING`) dropped; identifier/device/email/mobile constants kept |
| `notification.domain.NotificationCode` | `notification.domain.NotificationCode` | Verbatim |
| `notification.domain.NotificationRequest` | `notification.domain.NotificationRequest` | Getters added (`getType`, `getDeviceId`, `getEmailAddress`, `getMobile`, `getNotificationCode`) — original relied on AMQP/Jackson field serialization only; a real `Notifier` now needs typed in-process access |
| `notification.repository.NotificationCodeRepository` | `notification.repository.NotificationCodeRepository` | Verbatim |
| `notification.utils.CodeGeneration` | `notification.utils.CodeGeneration` | `generateSimpleCode()` reimplemented without commons-lang3 (see Decisions) |
| `notification.aop.NotificationAspect` | `notification.aop.NotificationAspect` | Depends on new `Notifier` instead of AMQP `NotificationPublisher`; `StringUtils.isNotEmpty` replaced with inline check |
| `notification.amqp.NotificationPublisher` | **excluded** — replaced by `io.helixiam.notification.Notifier` (new interface) + `io.helixiam.notification.LoggingNotifier` (new no-op/log fallback `@Component`) | Real SMTP/HTTP/push implementations are a later task |

## Vendored beyond the Task 1 list (transitive dependencies)

These types were not in the Task 1 file list but were required to compile classes that *are* on
the list, and were vendored under a sensible `io.helixiam.*` package per the task's hard
constraints:

| Old FQN | New FQN | Why / deviation |
|---|---|---|
| `group.mfnr.subscriber.starter.validation.exception.AbstractValidationException` (module `mfnr-subscriber-starter-validation`) | `io.helixiam.common.exception.AbstractValidationException` | Interface `ValidationException` implements; verbatim |
| `group.mfnr.subscriber.starter.validation.exception.ValidationException` | `io.helixiam.common.exception.ValidationException` | **Base class changed**: originally `extends org.springframework.amqp.AmqpRejectAndDontRequeueException` (a RabbitMQ type — a hard "zero amqp/rabbit references" violation). Now `extends RuntimeException`. All fields/behavior otherwise unchanged. `DatabaseException` (Task 1 list) extends this. |
| `group.mfnr.subscriber.starter.validation.exception.DuplicateException` | `io.helixiam.common.exception.DuplicateException` | Verbatim (extends the de-AMQP'd `ValidationException`); `DatabaseExceptionHandler` (Task 1 list) throws this |
| `group.mfnr.subscriber.starter.annotation.notification.Notification` (module `mfnr-subscriber-starter-annotations`) | `io.helixiam.notification.annotation.Notification` | Verbatim; drives `NotificationAspect` (Task 1 list) |
| `group.mfnr.subscriber.starter.annotation.notification.NotificationEmail` | `io.helixiam.notification.annotation.NotificationEmail` | Verbatim |
| `group.mfnr.subscriber.starter.annotation.notification.NotificationIdentifier` | `io.helixiam.notification.annotation.NotificationIdentifier` | Verbatim |
| `group.mfnr.subscriber.starter.annotation.notification.NotificationMediaType` | `io.helixiam.notification.annotation.NotificationMediaType` | Verbatim |
| — (new) | `io.helixiam.notification.Notifier` | New interface replacing AMQP `NotificationPublisher`; 3 methods (`sendEmailNotification`/`sendSmsNotification`/`sendAppNotification`), same signatures |
| — (new) | `io.helixiam.notification.LoggingNotifier` | New `@Component @ConditionalOnMissingBean(Notifier.class)` no-op/log fallback so the context starts before a real delivery channel exists |

## Decisions / deviations (full detail)

1. **AMQP base class removed from the validation exception hierarchy.**
   `ValidationException` (pulled in transitively as the base of `DatabaseException`) originally
   extended `org.springframework.amqp.AmqpRejectAndDontRequeueException`, a RabbitMQ listener
   type controlling reject-and-don't-requeue semantics for a failed AMQP consumer. HelixIAM has
   no broker, so it now extends plain `RuntimeException`. All fields (`validation` map,
   `errorCode`, `authorization`), constructors, and the `fillInStackTrace()` override (perf
   optimization — this exception carries no useful stack trace) are preserved unchanged.

2. **`starter-validation` and `starter-annotations` modules were not in the Task 1 list but had
   to be partially vendored.** Only the specific types actually referenced by the Task 1 classes
   were pulled in (`AbstractValidationException`/`ValidationException`/`DuplicateException` from
   `starter-validation`; the four `notification.*` annotations from `starter-annotations`) — not
   the full modules (e.g. `Validator`, `EqualFieldsValidator`, `AuthorizationException`,
   `@ValidIPv4`, `@EqualFields` were left behind as out of scope).

3. **`NotificationPublisher` (AMQP) → `Notifier` (plain interface) + `LoggingNotifier` (fallback).**
   Per the task brief: `Notifier` declares the same three methods
   (`sendEmailNotification`/`sendSmsNotification`/`sendAppNotification`, each taking a
   `NotificationRequest`) that `NotificationPublisher` exposed as `@AnonymousSender`-annotated
   AMQP sends. `NotificationAspect` now calls `Notifier` directly (synchronous, in-process) instead
   of publishing to a RabbitMQ exchange. `LoggingNotifier` is a `@Component` with
   `@ConditionalOnMissingBean(Notifier.class)` that logs a warning instead of delivering, so the
   Spring context can start with no NPE before a later task adds SMTP/HTTP/log implementations.
   Caveat noted in `LoggingNotifier`'s Javadoc: `@ConditionalOnMissingBean` ordering between two
   plain component-scanned beans isn't strictly guaranteed by Spring; a later task adding a real
   `Notifier` should use `@Primary` (or move this fallback to an `@AutoConfiguration`) to be safe.

4. **`NotificationConstant`**: dropped the AMQP routing/exchange constants
   (`VIRTUALHOST_NOTIFICATION`, `EXCHANGE_NOTIFICATION`, `NOTIFICATION_EMAIL_ROUTING`,
   `NOTIFICATION_SMS_ROUTING`, `NOTIFICATION_APP_ROUTING`) since there's no broker/exchange to
   route through anymore. Kept the non-AMQP constants (`MODULE_NAME`, `IDENTIFIER`, `DEVICE_ID`,
   `MOBILE_PHONE`, `EMAIL`).

5. **`StarterLoggingProperties`**: dropped the `amqpBridge`/`amqpFederate` `LogLevel` fields
   (meaningless with no broker) and renamed the `@ConfigurationProperties` prefix from
   `mfnr.subscriber.starter.logging` to `helixiam.logging`. Other field names
   (`cacheOrchestrator`, `subscriberEngine`, etc.) were left as-is — they're just log-category
   knobs, not otherwise referenced by any vendored class, and renaming them is not required to
   satisfy the "zero group.mfnr / zero amqp" constraints.

6. **`commons-lang3` is not a `helix-iam-server` dependency** (confirmed via
   `mvn dependency:tree` — not pulled transitively by anything in the pom), so two usages were
   replaced with dependency-free equivalents rather than adding a new third-party dependency:
   - `CodeGeneration.generateSimpleCode()`: originally
     `org.apache.commons.lang3.RandomStringUtils.random(10, 0, 0, true, false, null, new SecureRandom())`
     (a 10-char, letters-only, `SecureRandom`-backed string). Reimplemented with a plain
     `SecureRandom` draw over the same `A-Za-z` alphabet, same length — behaviorally equivalent.
   - `NotificationAspect`: `org.apache.commons.lang3.StringUtils.isNotEmpty(identifier)` replaced
     with an inline `value != null && !value.isEmpty()` check (identical semantics to
     commons-lang3's `isNotEmpty`, which is exactly "non-null and non-empty", as opposed to
     Spring's `StringUtils.hasText`, which also excludes whitespace-only strings and would *not*
     have been behaviorally identical).

7. **AspectJ (`@Aspect`, `@Around`, `@AfterThrowing`, `ProceedingJoinPoint`, etc.) needed no pom
   change.** `org.aspectj:aspectjweaver` is already on the compile classpath transitively via
   `org.springframework:spring-aspects`, which `spring-boot-starter-data-jpa` → `spring-data-jpa`
   pulls in. Confirmed via `mvn dependency:tree`. Spring Boot's AOP auto-configuration
   (`spring-boot-autoconfigure`, already present) auto-enables proxying for `@Aspect` beans when
   `spring-aop`/`aspectjweaver` are present, so no explicit `spring-boot-starter-aop` dependency
   or `@EnableAspectJAutoProxy` was added. If a later task hits an AOP proxying issue at runtime,
   check `spring.aop.auto`/`spring.aop.proxy-target-class` first before assuming a missing
   dependency.

8. **`NotificationRequest` getters added** (`getType`, `getDeviceId`, `getEmailAddress`,
   `getMobile`, `getNotificationCode`). The original class only had setters (plus
   `getAdditionalData()`) because it only ever needed to be Jackson-serialized onto an AMQP
   message body (field-level `@JsonProperty` is enough for that) and deserialized on the
   subscriber side. With AMQP gone, a `Notifier` implementation (SMTP/HTTP/etc., a later task)
   receives the `NotificationRequest` object directly and needs typed accessors to read it — so
   getters were added. No existing behavior changed; this is purely additive.

9. **Single-datasource startup**: `DataSourceConfiguration`/`ReadWriteRoutingDataSource` were
   vendored faithfully; no change was needed to satisfy "must start with a single datasource" —
   the original code already falls back to routing both `UPDATABLE` and `READONLY` lookup keys to
   the same read-write `HikariDataSource` when `spring.readonly.datasource.url` is unset
   (`DataSourceConfiguration.dataSource()`, `StringUtils.hasText(readOnlyUrl)` branch).

## What was intentionally left out (later tasks)

- `notification.amqp.NotificationPublisher` (the AMQP interface itself) — superseded by `Notifier`.
- Any concrete `Notifier` implementation (SMTP via `jakarta.mail`/`angus-mail`, HTTP webhook, etc.)
  — a later task per the brief.
- The rest of `starter-validation` (`Validator`, `EqualFieldsValidator`, `AuthorizationException`,
  `@ValidIPv4`, `@EqualFields`) and `starter-annotations` beyond the four notification annotations
  — out of scope for Task 1.
- Business source, controllers, `authorization-server-*` code — explicitly out of scope per the
  task brief; a later task.

---

## Task 2: subscriber (business + persistence) fold

Task 2 folded `authorization-server-subscriber/src/main/java/group/**` (357 files: 356 under
`group.mfnr.authorization.*` + `group/mfnr/Application.java`) and
`authorization-server-subscriber/src/main/resources/*` into `helix-iam-server`, deleted the AMQP
transport layer, and rewrote the business code's infra imports against the Task 1 table above.
`group.mfnr.authorization.*` package names were kept as-is (no rename — that's a separate later
pass). Result: 350 main source files compile green (`mvn -o clean compile`).

### Deleted (AMQP transport layer — 40 files, all of `group/mfnr/authorization/amqp/` except
### `RealmScopedKey`, which moved out first — see below)

All 39 `@Subscriber`/`@AnonymousListener` classes (`AccountIdentitySubscriber`,
`AdminRbacSubscriber`, `AgentIdentitySubscriber`, `ApplicationConfigSubscriber`,
`AuditLogSubscriber`, `AuthorizationStoreSubscriber`, `AuthorizationSubscriber`,
`ClaimScopeSubscriber`, `ClientAdminSubscriber`, `ClientMapperSubscriber`, `ClientRoleSubscriber`,
`CredentialSubscriber`, `DeviceEnrollmentSubscriber`, `FederatedIdentitySubscriber`,
`FlowAdminSubscriber`, `FlowSubscriber`, `GdprAdminSubscriber`, `GroupAdminSubscriber`,
`HttpSessionStoreSubscriber`, `IdentityProviderConfigSubscriber`, `LoginSubscriber`,
`MessagingAdminSubscriber`, `OrganizationAdminSubscriber`, `ProvisioningAdminSubscriber`,
`RealmAdminSubscriber`, `RealmKeyConfigSubscriber`, `RecoveryCodeSubscriber`,
`ResourceIndicatorSubscriber`, `RiskSubscriber`, `RoleAdminSubscriber`,
`SamlRelyingPartyConfigSubscriber`, `ScimTargetConfigSubscriber`, `ServiceProviderSubscriber`,
`TenantSubscriber`, `UserAdminSubscriber`, `UserSubscriber`, `WebAuthnSubscriber`,
`WebhookConfigSubscriber`, `WorkloadIdentityConfigSubscriber`) plus `AmqpConstant` (routing-key
constants, transport-only). These were pure unwrap-call-wrap transport (verified: the subscriber
makes zero outbound AMQP calls); the logic they called lives on in the `service/*` classes, which
survive untouched.

### Moved, not deleted: `RealmScopedKey`

`group.mfnr.authorization.amqp.RealmScopedKey` → `group.mfnr.authorization.support.RealmScopedKey`
(package declaration updated; body verbatim). It has zero AMQP dependency (plain string
pack/split utility for a realm+key pair) and, per its own javadoc, is formatted by
`RegisteredClientRepositoryService` on the **publisher** side — not yet folded (a later task), so
it currently has no in-repo importer, but is kept per the task brief rather than deleted with the
rest of `amqp/`.

`group.mfnr.authorization.domain.LoginCredentials` needed no change — it already lived under
`domain/`, not `amqp/`.

### New: vendored beyond the Task 1 list (found only now, folding the business code)

Task 1's table didn't cover these — the business code (not the Task-1-listed infra classes)
imports them. Per the task brief ("if the business code imports a `group.mfnr.subscriber.starter.*`
type NOT in the map, STOP and report it") these are called out explicitly rather than silently
folded in:

| Old FQN | New FQN | Used by | Notes |
|---|---|---|---|
| `group.mfnr.subscriber.starter.security.utils.RSAKeyReader` (module `starter-security`) | `io.helixiam.common.security.RSAKeyReader` | `service.key.KeyMaterialService` (reads the master realm's signing key pair from PEM/DER) | Deviation: original used `org.apache.commons.io.IOUtils.toString(InputStream, Charset)`; commons-io is not a helix-iam-server dependency (confirmed via `mvn -o dependency:tree`, same check as VENDOR-MAP decision #6 for commons-lang3), so reimplemented with dependency-free `InputStream.readAllBytes()` + `new String(bytes, charset)` — behaviorally identical for this use. No AMQP dependency in the original. |
| `group.mfnr.subscriber.starter.security.exception.KeyHandlingException` (module `starter-security`) | `io.helixiam.common.exception.KeyHandlingException` | (thrown by `RSAKeyReader`) | Verbatim — trivial `RuntimeException` subclass |
| `group.mfnr.subscriber.starter.security.utils.SecurityContext` (module `starter-security`) | `io.helixiam.common.security.SecurityContext` | `service.TenantService` (reads the calling user's id off the request's Spring Security `Authentication`) | Verbatim — plain Spring Security API, no AMQP dependency in the original |

`commons-lang3:3.17.0` (used by `LoginService`'s `org.apache.commons.lang3.StringUtils.isEmpty`)
needed **no vendoring or reimplementation** for Task 2: unlike the Task 1 infra classes, it's
already on the compile classpath transitively (confirmed via `mvn -o dependency:tree`) — via OpenSAML 5's
`velocity-engine-core` (`opensaml-saml-impl` → `shib-velocity`; `spring-security-saml2-service-provider` is no
longer a dependency since the M7 cleanup). Left as a direct
`org.apache.commons.lang3` import, unchanged from the subscriber source.

### Refactored (not vendored): `ResponseException`

`group.mfnr.subscriber.starter.amqp.exception.ResponseException` — package is under `amqp.*`, so
per the task brief it may **not** remain under any name (unlike the `starter-security` classes
above, which live outside the amqp namespace and were fair game to vendor as-is). Its only use was
`ServiceProviderService.save(...)`, wrapping a persistence failure to carry back over the wire
(`message`/`errorCode`/`authorization`/`validation` fields, Jackson-serializable for the AMQP
reply). With no wire to carry it over, this now throws the already-vendored (Task 1)
`io.helixiam.common.exception.ValidationException` instead — same shape (message + errorCode +
authorization), unchecked (`RuntimeException`), so `save(...)`'s `throws ResponseException` was
dropped from the signature. `ResponseException` itself (the class) was not vendored under any
package; there is no remaining reference to it anywhere in `helix-iam-server`.

### Notification: `NotificationPublisher` → `Notifier`

`service.UserService` was the only business-code caller of `NotificationPublisher` (the
AMQP-`@AnonymousSender` interface). Rewired per Task 1's `Notifier` interface: field/constructor
parameter renamed `notificationPublisher` → `notifier` (type `io.helixiam.notification.Notifier`),
and its one call site (`notificationPublisher.sendEmailNotification(...)` inside
`verifyEmail(...)`) now calls `notifier.sendEmailNotification(...)` — identical signature, so no
other change was needed. `UserService`'s `@Notification`-annotated methods (`save`,
`resetPasswordRequest`) needed no change at all: the vendored `io.helixiam.notification.aop.
NotificationAspect` (Task 1) already dispatches through `Notifier` generically for any
`@io.helixiam.notification.annotation.Notification`-annotated method, business code included —
folding `UserService` under that aspect's scan just worked once `Application`'s
`scanBasePackages` covered `io.helixiam` (see below). Real delivery still awaits a `Notifier`
implementation (SMTP/HTTP) — a later task; `LoggingNotifier` (Task 1) is the fallback meanwhile.

### Mechanical rewrites (per the Task 1 table, no new decisions)

8 JPA entity classes' `group.mfnr.subscriber.starter.database.security.AttributeEncryption` →
`io.helixiam.persistence.security.AttributeEncryption` (verbatim swap, one import line each):
`domain.ServiceProviderOAuthClient`, `domain.webhook.WebhookSubscription`, `domain.scim.ScimTarget`,
`domain.user.UserCredentials`, `domain.mfa.HotpCredentialEntity`,
`domain.messaging.MessagingProvider`, `domain.realm.RealmKey`, `domain.saml.SamlRelyingPartyEntity`.

`service.UserService`'s remaining three notification imports (`NotificationCodeRepository`,
`NotificationRequest`, and the three `@Notification`/`@NotificationEmail`/`@NotificationMediaType`
annotations) swapped 1:1 to their `io.helixiam.notification.*` equivalents per the Task 1 table —
no signature/behavior changes needed (Task 1 already made `NotificationRequest` a plain typed
class with getters, and `NotificationCodeRepository`/the annotations are verbatim).

### Application entry point

`group.mfnr.Application` (`@SpringBootApplication`) kept as the merged entry point, per the task
brief — the publisher's own `Application` class (not yet folded) reconciles with this one in a
later task. Changed `@SpringBootApplication` → `@SpringBootApplication(scanBasePackages =
{"group.mfnr", "io.helixiam"})`: `io.helixiam` is a sibling top-level package to `group.mfnr`, so
the default scan (the annotated class's own package and below) would otherwise miss all of it —
not just its `@Component`/`@Aspect`/`@Configuration` beans (e.g. `NotificationAspect`,
`DataSourceConfiguration`, `LoggingNotifier`), but also its JPA entities/repositories
(`io.helixiam.notification.domain.NotificationCode`,
`io.helixiam.notification.repository.NotificationCodeRepository`), since Spring Boot's JPA
auto-configuration derives its entity-scan/repository-scan base packages from the same
`AutoConfigurationPackages` registration that `scanBasePackages` feeds.

### Not folded (per the task brief)

- `authorization-server-publisher` (the OAuth2/OIDC/SAML front + `RegisteredClientRepositoryService`
  that formats a `RealmScopedKey`) — later task.
- `src/test` (both subscriber and any future publisher tests) — later task.
- Any real `Notifier` implementation (SMTP/HTTP) — later task, same as Task 1 left it.

### No genuine cross-service seam found

Per the task brief's stop condition ("if you hit an error that reveals a genuine cross-service
dependency... STOP and report it rather than stubbing blindly") — none was found. Every
`group.mfnr.subscriber.starter.*` import the business code had was resolvable in-process (either
already in the Task 1 map, or a small self-contained utility with no AMQP dependency, vendored
above), and the one truly AMQP-shaped type (`ResponseException`) had exactly one call site that
refactors cleanly onto the existing `ValidationException` hierarchy. `RealmScopedKey` is the one
class kept for a *future* cross-service caller (the publisher's client-lookup path) but that
caller doesn't exist in this repo yet, so it's inert, not a seam.

---

## EUDI Wallet verifier: direct third-party libraries (wallet Task 6)

Nothing is vendored for the wallet verifier (pure Java, no kotlin-stdlib, no EUDI reference libraries). It depends
directly on two libraries that were already on the classpath. They are listed here so the wallet code's external
surface is explicit.

| Library | Coordinates | Version source | Used by | Notes |
|---|---|---|---|---|
| Nimbus JOSE + JWT | `com.nimbusds:nimbus-jose-jwt` | `${nimbus-jose-jwt.version}` (**10.10**) in this pom's `dependencyManagement` | `io.helixiam.authorization.federation.wallet.*` (SD-JWT issuer JWT, KB-JWT, JWE `ECDH-ES` response decryption, JWK thumbprints) | Also used by Spring Security 7.1 (`spring-security-oauth2-jose`, the authorization server). **Spring Boot 4.1 does not manage it** (neither did 3.5), so the `<dependency>` is version-less and the version is pinned once in `dependencyManagement`. **Security:** pinned to 10.10 because of CVE-2025-53864 / GHSA-xwmg-2g98-w7v9 (unbounded nesting in JWT claim-set JSON; affects < 9.37.4 and 9.38-rc1 .. < 10.0.2). Spring Security 7.1.1 passes the full suite on 10.10; `NimbusNestedJsonRegressionTest` guards the fix. `mvn dependency:tree -Dverbose` shows a single 10.10. Apache-2.0. |
| Jackson CBOR | `com.fasterxml.jackson.dataformat:jackson-dataformat-cbor` | Jackson 2 BOM, `${jackson-2-bom.version}` (**2.21.7**, overriding Spring Boot 4.1's 2.21.5) | `wallet.mdoc.StrictCbor` (the only CBOR entry point for wallet input) | Already a direct pom dependency (no other main-code import of it today). Used only through `CBORParser` token streaming with Helix's own depth/item/byte counters, never `readTree`. Features `READ_UNDEFINED_AS_EMBEDDED_OBJECT` and `READ_SIMPLE_VALUE_AS_EMBEDDED_OBJECT` (2.20+) are enabled so undefined/simple values can be refused. Apache-2.0. |
| BouncyCastle (`bcprov-jdk18on` / `bcpkix-jdk18on` / `bcutil-jdk18on`) | `org.bouncycastle:bcprov-jdk18on`, `:bcpkix-jdk18on`, `:bcutil-jdk18on` | **1.86** (`${bouncycastle.version}`, direct `<dependency>` pins in this pom, not transitive — kept uniform so OpenSAML/cryptacular's own older transitive BC version never collides) | `wallet.trust.IssuerTrustValidator` / `TrustAnchors` (PKIX chain building/validation against the provider's configured PID trust anchors, PEM parsing); `service.key.SoftwareRealmSigningKeys` (verifier access-key import, shared with the wallet's `/verifier-keys` admin API) | Already a direct pom dependency for other callers (eID/SAML key handling, the pre-wallet security review's dependency-scan table lists `bcprov/bcpkix/bcutil` at 1.81 — now 1.86, same pin). The wallet code adds no new BouncyCastle usage pattern: it is `java.security.cert.CertPathValidator`/PKIX APIs with BC as the JCE provider, the same as `AttributeEncryption`'s AES/GCM. MIT-style BouncyCastle licence. |
| ZXing core (`com.google.zxing:core`, via `com.google.zxing:javase`) | `com.google.zxing:javase` (brings in `core` transitively) | 3.5.4 (already a dependency, reused — see the plan summary's library table) | `wallet.web.QrCodeSvg` (server-side QR rendering for the cross-device invocation link) | Only the encoder (`QRCodeWriter`/`BitMatrix`, `core`) is used, rendered to an inline SVG — no image codec, no AWT dependency pulled into the response path despite `javase` bringing AWT-based helpers transitively. No wallet-specific fork or wrapper; called directly. Apache-2.0. |

---

## Platform: Spring Boot 4.1 (framework-major upgrade)

| Component | Version | Notes |
|---|---|---|
| Spring Boot | **4.1.1** (`spring-boot-starter-parent`) | Modular starters: `spring-boot-starter-webmvc`, `spring-boot-starter-security-oauth2-authorization-server` (renamed), `spring-boot-starter-flyway` (Flyway auto-configuration is its own module now), `spring-boot-starter-session-data-redis`; test: `spring-boot-starter-webmvc-test`, `spring-boot-starter-security-test`, `spring-boot-resttestclient`. Logback is excluded from the web starter (Log4j2 only). |
| Spring Framework | **7.0.9** (Boot-managed) | First public release with the fix for CVE-2026-47884 / CVE-2026-47890 (spring-webmvc). |
| Spring Security | **7.1.1** (Boot-managed), incl. the OAuth2 authorization server (`spring-security-oauth2-authorization-server` 7.1.1, formerly Spring Authorization Server 1.5.8) | `OAuth2AuthorizationServerConfiguration.applyDefaultSecurity` was removed; `SecurityConfig` applies the same three steps itself. `AntPathRequestMatcher` was removed; `PathPatternRequestMatcher` replaces it (the realm filter's virtual context path is honoured). `AuthorizationManager#check` became `#authorize`. Stored authorizations from 1.0 are read through `LegacyAuthorizationServerSerialization` (the authorization server's shared 1.x `serialVersionUID` was replaced per class). |
| Spring Session | **4.1.1** (Boot-managed) | |
| Hibernate ORM | **7.4.5.Final** (Boot-managed) | |
| Tomcat | **11.0.24** (Boot-managed; Jakarta EE 11 / Servlet 6.1) | The 1.0 pin to 10.1.61 is gone. |
| Flyway | **12.4.0** (Boot-managed, `flyway-core` + `flyway-database-postgresql`) | Was 11.20.3 (explicit). |
| springdoc-openapi | **3.1.1** | The Spring Boot 4 line (was 2.9.1). |
| Jackson | 2.21.7 (`com.fasterxml.jackson`, the application) and 3.2.3 (`tools.jackson`, webauthn4j / Flyway / Spring Security internals), annotations **2.22** for both | The application stays on Jackson 2 through the deprecated `spring-boot-jackson2` module; `spring.http.converters.preferred-json-mapper=jackson2` keeps Spring MVC's wire format. |
| Testcontainers | **2.0.5** (Boot-managed; `testcontainers-postgresql`, `testcontainers-junit-jupiter`) | Test only. |
| Netty | 4.2.x (Boot-managed, via Lettuce) | The 1.0 pin to 4.1.139.Final is gone. |
| pgjdbc | 42.7.13 (Boot-managed) | The 1.0 pin to 42.7.12 is gone. |
