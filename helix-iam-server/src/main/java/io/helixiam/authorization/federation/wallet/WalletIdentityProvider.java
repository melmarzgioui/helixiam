/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.wallet;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import io.helixiam.authorization.federation.PresentedProvider;
import io.helixiam.authorization.federation.spi.BrokeredIdentity;
import io.helixiam.authorization.federation.spi.IdentityProvider;
import io.helixiam.authorization.federation.spi.IdpMetadata;
import io.helixiam.authorization.federation.wallet.dcql.DcqlQueryBuilder;
import io.helixiam.authorization.federation.wallet.dcql.DcqlResultMatcher;
import io.helixiam.authorization.federation.wallet.status.StatusPolicy;
import io.helixiam.authorization.federation.wallet.status.TokenStatusListClient;
import io.helixiam.authorization.federation.wallet.transaction.WalletTransaction;
import io.helixiam.authorization.federation.wallet.transaction.WalletTransactionCapacityException;
import io.helixiam.authorization.federation.wallet.transaction.WalletTransactionStore;
import io.helixiam.authorization.federation.wallet.trust.TrustAnchors;
import io.helixiam.authorization.security.audit.AuditLog;
import io.helixiam.authorization.service.key.SigningKeyHandle;
import io.helixiam.common.log.LogSafe;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.web.util.UriUtils;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * The EUDI Wallet (OpenID4VP verifier) on the federation SPI: "Sign in with EUDI Wallet" for a realm. Built and
 * validated by {@link WalletIdentityProviders}; one instance per configured provider, holding that provider's
 * verifier components.
 *
 * <ul>
 *   <li>{@link #start}: creates a {@code CREATED} {@link WalletTransaction} (128-bit nonce; an ephemeral P-256
 *       {@code ECDH-ES} decryption key with a random {@code kid}; distinct random same-device and cross-device request
 *       ids and response id; {@code helixState} = the broker's state; the browser binding hash; the PID DCQL query; the
 *       configured TTL) and sends the browser to Helix's own wallet page
 *       {@code /realms/<realm>/broker/<alias>/wallet?tx=<transactionId>} (Task 18 serves it, and the request and
 *       response endpoints). A stored provider starts only in its own realm ({@link #keyRealm()}); a YAML provider
 *       (key in master) in any.</li>
 *   <li>{@link #callback}: redeems {@code response_code} with the broker's expected state and this browser's binding
 *       ({@link WalletTransactionStore#redeem}, single use, constant time) and returns the identity stored at
 *       verification ({@link VerifiedIdentityJson}). Every refusal is a {@link WalletVerificationException}; the broker
 *       logs its reason and answers only {@code /login?error=federation}, so the browser never learns which check
 *       failed.</li>
 *   <li>{@link #logout}: a no-op (a wallet has no session to end).</li>
 * </ul>
 *
 * <h2>What Task 18's endpoints use</h2>
 * The registry hands out providers by alias, possibly wrapped in a {@link PresentedProvider}; {@link #from} unwraps.
 * Then: {@link #config()}, {@link #signingKey()} (the validated handle; its chain is the {@code x5c}),
 * {@link #transactions()}, {@link #verifiers()} (by format, each with this provider's limits and status client),
 * {@link #matcher()}, {@link #decryptor()} and {@link #verificationContext} (the per-transaction context, with the same
 * {@link #statusPolicy()} instance the status client enforces).
 *
 * <p>Never logged: nonces, codes, keys, the binding or the state. Logged: transaction id, alias, realm, reason.
 */
public final class WalletIdentityProvider implements IdentityProvider {

    /** The built-in login-button mark: a neutral wallet, never an EU emblem. */
    public static final String ICON_KEY = "eudi-wallet";
    /** The callback parameter carrying the response code (OpenID4VP §8.2 {@code response_code}). */
    public static final String RESPONSE_CODE_PARAM = "response_code";
    /**
     * Task 18 fix round 1: the {@link RedirectResponse#parameters()} entry carrying the new transaction's id, so the
     * broker can remember it in the session and discard it when the same browser starts again (one live wallet login
     * per browser). Never sent anywhere.
     */
    public static final String TRANSACTION_PARAM = "walletTransactionId";
    /** Verify-only mode: the realm-relative browser callback of a VERIFY transaction (the flow step's). */
    public static final String VERIFY_CALLBACK_PATH = "/flow/wallet/callback";

    private static final Logger LOG = LogManager.getLogger(WalletIdentityProvider.class);
    private static final int ID_BYTES = 32;
    private static final int NONCE_BYTES = 16;
    private static final int KID_BYTES = 16;

    private final WalletProviderConfig config;
    /** The realm a stored provider (and its key) belongs to; null for a YAML provider, which serves every realm. */
    private final String keyRealm;
    private final SigningKeyHandle signingKey;
    /** Read at every verification: pasted anchors are fixed, trusted-list anchors follow their refreshes. */
    private final java.util.function.Supplier<TrustAnchors> trustAnchors;
    /** Whether the "anchor without SubjectKeyIdentifier" WARN was logged (once per built provider, never per login). */
    private final java.util.concurrent.atomic.AtomicBoolean warnedMissingSki =
            new java.util.concurrent.atomic.AtomicBoolean();
    private final StatusPolicy statusPolicy;
    private final TokenStatusListClient statusClient;
    private final Map<String, PresentationVerifier> verifiers;
    private final DcqlQueryBuilder queryBuilder = new DcqlQueryBuilder();
    private final DcqlResultMatcher matcher = new DcqlResultMatcher();
    private final VpResponseDecryptor decryptor = new VpResponseDecryptor();
    private final WalletTransactionStore transactions;
    private final Clock clock;
    private final AuditLog audit;
    private final SecureRandom random = new SecureRandom();

    WalletIdentityProvider(final WalletProviderConfig config, final String keyRealm, final SigningKeyHandle signingKey,
                           final TrustAnchors trustAnchors, final StatusPolicy statusPolicy,
                           final TokenStatusListClient statusClient, final Map<String, PresentationVerifier> verifiers,
                           final WalletTransactionStore transactions, final Clock clock, final AuditLog audit) {
        this(config, keyRealm, signingKey, fixed(trustAnchors), statusPolicy, statusClient, verifiers, transactions,
                clock, audit);
    }

    WalletIdentityProvider(final WalletProviderConfig config, final String keyRealm, final SigningKeyHandle signingKey,
                           final java.util.function.Supplier<TrustAnchors> trustAnchors,
                           final StatusPolicy statusPolicy, final TokenStatusListClient statusClient,
                           final Map<String, PresentationVerifier> verifiers,
                           final WalletTransactionStore transactions, final Clock clock, final AuditLog audit) {
        this.config = Objects.requireNonNull(config, "config");
        this.keyRealm = keyRealm;
        this.signingKey = Objects.requireNonNull(signingKey, "signingKey");
        this.trustAnchors = Objects.requireNonNull(trustAnchors, "trustAnchors");
        this.statusPolicy = Objects.requireNonNull(statusPolicy, "statusPolicy");
        this.statusClient = Objects.requireNonNull(statusClient, "statusClient");
        this.verifiers = Map.copyOf(verifiers);
        this.transactions = Objects.requireNonNull(transactions, "transactions");
        this.clock = Objects.requireNonNull(clock, "clock");
        this.audit = Objects.requireNonNull(audit, "audit");
    }

    /** The wallet provider behind {@code provider} (unwrapping a {@link PresentedProvider}), if it is one. */
    public static Optional<WalletIdentityProvider> from(final IdentityProvider provider) {
        IdentityProvider p = provider;
        while (p instanceof PresentedProvider presented) {
            p = presented.delegate();
        }
        return p instanceof WalletIdentityProvider wallet ? Optional.of(wallet) : Optional.empty();
    }

    @Override
    public IdpMetadata metadata() {
        return IdpMetadata.of(config.alias(), IdpMetadata.Protocol.WALLET,
                config.displayName() == null ? config.alias() : config.displayName(), ICON_KEY, null);
    }

    // ------------------------------------------------------------------------------------------------ start

    @Override
    public RedirectResponse start(final AuthnRequestContext context) {
        return start(context, WalletTransaction.Purpose.LOGIN, null);
    }

    /**
     * Task 21b: starts a {@link WalletTransaction.Purpose#LINK} transaction for the signed-in {@code userId} (the
     * account console's "Link EU Digital Identity Wallet"; the caller enforces the authentication and the recent
     * sign-in). The same wallet page, request and response endpoints serve it; its response only stores the resolved
     * subject, and only {@link #redeemLink} can redeem it: it never signs anyone in.
     *
     * @throws IllegalStateException without a user, realm, state or binding, or for a stored provider of another realm
     */
    public RedirectResponse startLink(final AuthnRequestContext context, final String userId) {
        if (blank(userId)) {
            throw new IllegalStateException("A wallet link needs the signed-in user");
        }
        return start(context, WalletTransaction.Purpose.LINK, userId);
    }

    /**
     * Verify-only mode: starts a {@link WalletTransaction.Purpose#VERIFY} transaction for the already identified
     * {@code userId} (the {@code eudi-wallet-verify} flow step). Same wallet page and endpoints; its response stores a
     * {@link VerifiedIdentityJson.Verification} and only {@link #redeemVerify} can redeem it. It never signs anyone in.
     *
     * @throws IllegalStateException without a user, realm, state or binding, for a provider that is not verify-only,
     *                               or for a stored provider of another realm
     */
    public RedirectResponse startVerify(final AuthnRequestContext context, final String userId) {
        if (!config.subject().verifyOnly()) {
            throw new IllegalStateException("Wallet provider '" + config.alias() + "' is not a verify-only connection");
        }
        if (blank(userId)) {
            throw new IllegalStateException("A wallet verification needs the identified user");
        }
        return start(context, WalletTransaction.Purpose.VERIFY, userId);
    }

    /** Whether this provider can sign anyone in (a verify-only connection cannot). */
    @Override
    public boolean signInCapable() {
        return !config.subject().verifyOnly();
    }

    private RedirectResponse start(final AuthnRequestContext context, final WalletTransaction.Purpose purpose,
                                   final String userId) {
        if (config.subject().verifyOnly() != (purpose == WalletTransaction.Purpose.VERIFY)) {
            // Design D7: a verify-only connection is never a first factor and never links; a login connection never
            // stands in for a verification.
            throw new IllegalStateException("Wallet provider '" + config.alias() + "' cannot start a " + purpose
                    + " transaction");
        }
        if (blank(context.realmId()) || blank(context.state())) {
            throw new IllegalStateException("A wallet login needs a realm and a state");
        }
        if (blank(context.browserBindingHash())) {
            throw new IllegalStateException("A wallet login needs a browser binding");
        }
        // The registry is keyed by alias only (spec conflict 6): a stored provider signs with its own realm's key and
        // must never start a login for another realm. The broker turns this into /login?error=federation.
        if (keyRealm != null && !keyRealm.equals(context.realmId())) {
            throw new IllegalStateException("Wallet provider '" + config.alias() + "' belongs to another realm");
        }
        final Instant now = clock.instant();
        final WalletTransaction tx = new WalletTransaction(token(ID_BYTES), token(ID_BYTES), token(ID_BYTES),
                token(ID_BYTES), context.realmId(), config.alias(), context.state(), context.browserBindingHash(),
                token(NONCE_BYTES), encryptionKey().toJSONString(), dcqlQuery(), null,
                WalletTransaction.Status.CREATED, null, null, null, now,
                now.plusSeconds(config.transactionTtlSeconds()), purpose, userId);
        // Context-relative: the broker answers "redirect:" + location, which Spring resolves under the realm's virtual
        // context path (/realms/<realm>), like the broker's own /login redirects.
        final String walletPage = "/broker/" + segment(config.alias()) + "/wallet";
        try {
            transactions.create(tx);
        } catch (final WalletTransactionCapacityException e) {
            // Task 18: a temporary condition, not a federation error: the wallet page says "try again later" (503).
            LOG.warn("Wallet login not started, the transaction store is full: alias={} realm={}",
                    LogSafe.sanitize(config.alias()), LogSafe.sanitize(context.realmId()));
            return new RedirectResponse(walletPage + "/unavailable", Map.of());
        }
        LOG.info("Wallet {} started: alias={} realm={} tx={}", purpose.name().toLowerCase(java.util.Locale.ROOT),
                LogSafe.sanitize(config.alias()), LogSafe.sanitize(context.realmId()), tx.transactionId());
        return new RedirectResponse(walletPage + "?tx=" + tx.transactionId(),
                Map.of(TRANSACTION_PARAM, tx.transactionId()));
    }

    /** The ephemeral response-decryption key of one transaction (private part included; the store drops it). */
    private ECKey encryptionKey() {
        try {
            return new ECKeyGenerator(Curve.P_256).keyUse(KeyUse.ENCRYPTION).algorithm(JWEAlgorithm.ECDH_ES)
                    .keyID(token(KID_BYTES)).secureRandom(random).generate();
        } catch (final JOSEException e) {
            throw new IllegalStateException("Could not generate the wallet response key", e);
        }
    }

    /**
     * HAIP §5 trusted_authorities for this provider (see {@link WalletProviderConfig#sendsTrustedAuthorities}). When it
     * is to be sent but an anchor has no SubjectKeyIdentifier, it is left out rather than guessed, with one WARN per
     * built provider (each config load builds one), never per login. An explicit On is refused at save time instead
     * ({@link WalletConfigValidator}); this covers the default and anchors that changed underneath.
     */
    private List<String> trustedAuthorityValues() {
        if (!config.sendsTrustedAuthorities()) {
            return List.of();
        }
        // the anchors as of now: trusted-list anchors follow their refreshes
        final TrustAnchors anchors = trustAnchors.get();
        final List<java.security.cert.X509Certificate> missing = anchors.withoutSubjectKeyIdentifier();
        if (!missing.isEmpty()) {
            if (warnedMissingSki.compareAndSet(false, true)) {
                LOG.warn("Wallet provider '{}': trusted_authorities left out of the DCQL query: trust anchor '{}' has "
                        + "no SubjectKeyIdentifier (the PKIX validation is unchanged)", LogSafe.sanitize(config.alias()),
                        LogSafe.sanitize(missing.get(0).getSubjectX500Principal().getName()));
            }
            return List.of();
        }
        return anchors.authorityKeyIdentifiers();
    }

    private String dcqlQuery() {
        try {
            return StrictJson.MAPPER.writeValueAsString(
                    queryBuilder.pidQuery(config.pid().toQuerySpec(), config.credentialFormats(),
                            trustedAuthorityValues()));
        } catch (final JsonProcessingException e) {
            throw new IllegalStateException("Could not encode the DCQL query", e);
        }
    }

    // ------------------------------------------------------------------------------------------------ callback

    @Override
    public BrokeredIdentity callback(final CallbackContext context) {
        final WalletTransaction tx = redeemTransaction(context, WalletTransaction.Purpose.LOGIN);
        return VerifiedIdentityJson.read(config.alias(), tx.verifiedIdentityJson());
    }

    /**
     * Task 18: what {@link #callback} redeems, with the account decision the response endpoint stored
     * ({@link VerifiedIdentityJson#readLogin}); the broker hands it to {@link WalletLoginCompleter}. Same checks and
     * refusals as {@link #callback}.
     */
    public VerifiedIdentityJson.StoredLogin redeem(final CallbackContext context) {
        final WalletTransaction tx = redeemTransaction(context, WalletTransaction.Purpose.LOGIN);
        // Task 22: the transaction id is this method's own knowledge (never serialized into the stored JSON).
        return VerifiedIdentityJson.readLogin(config.alias(), tx.verifiedIdentityJson())
                .withTransactionId(tx.transactionId());
    }

    /** Task 21b: what {@link #redeemLink} returns: the user who started the link and the wallet's resolved subject. */
    public record LinkRedemption(String initiatingUserId, WalletSubject subject) {
    }

    /**
     * Task 21b: redeems a {@link WalletTransaction.Purpose#LINK} transaction's response code, with the same checks as
     * {@link #callback} (state and browser binding, single use, constant time). A LOGIN transaction's code is refused
     * here, as a LINK transaction's code is refused by {@link #callback} and {@link #redeem}.
     */
    public LinkRedemption redeemLink(final CallbackContext context) {
        final WalletTransaction tx = redeemTransaction(context, WalletTransaction.Purpose.LINK);
        return new LinkRedemption(tx.initiatingUserId(), VerifiedIdentityJson.readLink(tx.verifiedIdentityJson()));
    }

    /** Verify-only mode: what {@link #redeemVerify} returns. */
    public record VerifyRedemption(String initiatingUserId, String transactionId,
                                   VerifiedIdentityJson.Verification verification) {
    }

    /**
     * Verify-only mode: redeems a {@link WalletTransaction.Purpose#VERIFY} transaction's response code with the same
     * checks as {@link #callback} (state, browser binding, single use, constant time). A LOGIN or LINK code is refused
     * here, and a VERIFY code is refused by every other redemption.
     */
    public VerifyRedemption redeemVerify(final CallbackContext context) {
        final WalletTransaction tx = redeemTransaction(context, WalletTransaction.Purpose.VERIFY);
        return new VerifyRedemption(tx.initiatingUserId(), tx.transactionId(),
                VerifiedIdentityJson.readVerify(tx.verifiedIdentityJson()));
    }

    private WalletTransaction redeemTransaction(final CallbackContext context,
                                                final WalletTransaction.Purpose purpose) {
        final String code = context.parameters() == null ? null : context.parameters().get(RESPONSE_CODE_PARAM);
        if (blank(code)) {
            throw refused(context.realmId(), purpose, WalletErrorCode.INVALID_RESPONSE,
                    "the callback has no response_code", null);
        }
        if (blank(context.expectedState())) {
            throw refused(context.realmId(), purpose, WalletErrorCode.STATE_MISMATCH,
                    "no wallet login is pending in this session", null);
        }
        if (blank(context.browserBindingHash())) {
            throw refused(context.realmId(), purpose, WalletErrorCode.BROWSER_MISMATCH,
                    "this browser holds no wallet login binding", null);
        }
        final WalletTransaction tx = transactions.redeem(code, context.expectedState(), context.browserBindingHash())
                .orElseThrow(() -> refused(context.realmId(), purpose, WalletErrorCode.REPLAY,
                        "response code unknown, expired, already used, or not this login's state and browser", null));
        if (!config.alias().equals(tx.providerAlias()) || !Objects.equals(tx.realmId(), context.realmId())) {
            throw refused(context.realmId(), purpose, WalletErrorCode.INVALID_RESPONSE,
                    "the transaction belongs to another provider or realm", tx.transactionId());
        }
        if (tx.purpose() != purpose) {
            // Task 21b: a LINK transaction never signs anyone in, and a login is never a link (the code is spent).
            throw refused(context.realmId(), purpose, WalletErrorCode.INVALID_RESPONSE,
                    "the transaction is not a " + purpose + " transaction", tx.transactionId());
        }
        LOG.info("Wallet login redeemed: alias={} realm={} tx={}", LogSafe.sanitize(config.alias()),
                LogSafe.sanitize(tx.realmId()), tx.transactionId());
        return tx;
    }

    /**
     * Task 22: every LOGIN redemption refusal (the callback path) is audited here, the one place all of
     * {@link #redeemTransaction} routes through — never a presentation's format/issuer DN (unknown at this layer, a
     * redemption refusal is about the code/state/binding handshake, not the presentation content). A LINK redemption
     * (Task 21b, the account console) is never audited as a wallet login: it is not one.
     */
    private WalletVerificationException refused(final String realmId, final WalletTransaction.Purpose purpose,
                                                final WalletErrorCode code, final String safeDetail,
                                                final String transactionId) {
        // DEBUG only: the broker logs the refusal once, at WARN, with its reason
        LOG.debug("Wallet callback refused: alias={} tx={} reason={}", LogSafe.sanitize(config.alias()),
                transactionId == null ? "-" : transactionId, code.reason());
        if (purpose == WalletTransaction.Purpose.LOGIN) {
            audit.emit(WalletLoginAudit.failure(realmId, transactionId, config.alias(), null, null, code));
        }
        return new WalletVerificationException(code, safeDetail);
    }

    /** No-op: a wallet presentation leaves no upstream session. */
    @Override
    public void logout(final LogoutContext context) {
        // nothing to end at the wallet
    }

    // ------------------------------------------------------------------------------------------------ Task 18 view

    /** Whether this provider serves {@code realmId}: a YAML provider every realm, a stored one only its own. */
    public boolean servesRealm(final String realmId) {
        return !blank(realmId) && (keyRealm == null || keyRealm.equals(realmId));
    }

    /**
     * Task 21b: the realm-relative path of the browser callback of {@code tx}: the broker's
     * {@code /broker/<alias>/callback} for a login, the account console's {@code /account/wallet/<alias>/callback} for
     * a link. The response code goes on it as {@code ?response_code=}.
     */
    public static String callbackPath(final WalletTransaction tx) {
        final String alias = segment(tx.providerAlias());
        return switch (tx.purpose()) {
            case LINK -> "/account/wallet/" + alias + "/callback";
            // verify-only: the flow step that started it (the flow knows the provider)
            case VERIFY -> VERIFY_CALLBACK_PATH;
            case LOGIN -> "/broker/" + alias + "/callback";
        };
    }

    /** The realm of a stored provider (its key's realm); {@code null} for a YAML provider, usable in every realm. */
    public String keyRealm() {
        return keyRealm;
    }

    /** The validated configuration. */
    public WalletProviderConfig config() {
        return config;
    }

    /** The validated access-certificate key; its {@code certificateChain()} is the request object's {@code x5c}. */
    public SigningKeyHandle signingKey() {
        return signingKey;
    }

    /** The full {@code client_id} ({@link AuthorizationRequestFactory#clientId}). */
    public String clientId() {
        return AuthorizationRequestFactory.clientId(config, signingKey);
    }

    public WalletTransactionStore transactions() {
        return transactions;
    }

    /** Presentation verifiers by format ({@code dc+sd-jwt}, {@code mso_mdoc}), one per configured format. */
    public Map<String, PresentationVerifier> verifiers() {
        return verifiers;
    }

    public DcqlResultMatcher matcher() {
        return matcher;
    }

    public VpResponseDecryptor decryptor() {
        return decryptor;
    }

    /** The issuer trust as of now (trusted-list anchors included). */
    public TrustAnchors trustAnchors() {
        return trustAnchors.get();
    }

    private static java.util.function.Supplier<TrustAnchors> fixed(final TrustAnchors anchors) {
        final TrustAnchors value = Objects.requireNonNull(anchors, "trustAnchors");
        return () -> value;
    }

    /** The provider's status policy: the instance its {@link #statusClient()} enforces. */
    public StatusPolicy statusPolicy() {
        return statusPolicy;
    }

    public TokenStatusListClient statusClient() {
        return statusClient;
    }

    /**
     * The context the verifiers check a presentation of {@code tx} against.
     *
     * @param responseUri             the {@code response_uri} the request object named
     * @param encryptionJwkThumbprint the JWK SHA-256 thumbprint of the transaction's response key, or {@code null}
     *                                for unencrypted {@code direct_post} (the mdoc SessionTranscript input)
     */
    public VerificationContext verificationContext(final WalletTransaction tx, final String responseUri,
                                                   final byte[] encryptionJwkThumbprint) {
        return new VerificationContext(clientId(), tx.nonce(), responseUri, encryptionJwkThumbprint, clock.instant(),
                Duration.ofSeconds(config.clockSkewSeconds()), trustAnchors.get(), statusPolicy,
                config.pid().acceptedVcts(), config.pid().acceptedDoctype(), config.allowLegacyVcSdJwtTyp());
    }

    // ------------------------------------------------------------------------------------------------ helpers

    private String token(final int bytes) {
        final byte[] b = new byte[bytes];
        random.nextBytes(b);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(b);
    }

    private static String segment(final String value) {
        return UriUtils.encodePathSegment(value, StandardCharsets.UTF_8);
    }

    private static boolean blank(final String value) {
        return value == null || value.isBlank();
    }

    @Override
    public String toString() {
        return "WalletIdentityProvider[" + config.alias() + ", " + signingKey + "]";
    }
}
