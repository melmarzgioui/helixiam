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

    private static final Logger LOG = LogManager.getLogger(WalletIdentityProvider.class);
    private static final int ID_BYTES = 32;
    private static final int NONCE_BYTES = 16;
    private static final int KID_BYTES = 16;

    private final WalletProviderConfig config;
    /** The realm a stored provider (and its key) belongs to; null for a YAML provider, which serves every realm. */
    private final String keyRealm;
    private final SigningKeyHandle signingKey;
    private final TrustAnchors trustAnchors;
    private final StatusPolicy statusPolicy;
    private final TokenStatusListClient statusClient;
    private final Map<String, PresentationVerifier> verifiers;
    private final DcqlQueryBuilder queryBuilder = new DcqlQueryBuilder();
    private final DcqlResultMatcher matcher = new DcqlResultMatcher();
    private final VpResponseDecryptor decryptor = new VpResponseDecryptor();
    private final WalletTransactionStore transactions;
    private final Clock clock;
    private final SecureRandom random = new SecureRandom();

    WalletIdentityProvider(final WalletProviderConfig config, final String keyRealm, final SigningKeyHandle signingKey,
                           final TrustAnchors trustAnchors, final StatusPolicy statusPolicy,
                           final TokenStatusListClient statusClient, final Map<String, PresentationVerifier> verifiers,
                           final WalletTransactionStore transactions, final Clock clock) {
        this.config = Objects.requireNonNull(config, "config");
        this.keyRealm = keyRealm;
        this.signingKey = Objects.requireNonNull(signingKey, "signingKey");
        this.trustAnchors = Objects.requireNonNull(trustAnchors, "trustAnchors");
        this.statusPolicy = Objects.requireNonNull(statusPolicy, "statusPolicy");
        this.statusClient = Objects.requireNonNull(statusClient, "statusClient");
        this.verifiers = Map.copyOf(verifiers);
        this.transactions = Objects.requireNonNull(transactions, "transactions");
        this.clock = Objects.requireNonNull(clock, "clock");
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
                now.plusSeconds(config.transactionTtlSeconds()));
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
        LOG.info("Wallet login started: alias={} realm={} tx={}", LogSafe.sanitize(config.alias()),
                LogSafe.sanitize(context.realmId()), tx.transactionId());
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

    private String dcqlQuery() {
        try {
            return StrictJson.MAPPER.writeValueAsString(
                    queryBuilder.pidQuery(config.pid().toQuerySpec(), config.credentialFormats()));
        } catch (final JsonProcessingException e) {
            throw new IllegalStateException("Could not encode the DCQL query", e);
        }
    }

    // ------------------------------------------------------------------------------------------------ callback

    @Override
    public BrokeredIdentity callback(final CallbackContext context) {
        final WalletTransaction tx = redeemTransaction(context);
        return VerifiedIdentityJson.read(config.alias(), tx.verifiedIdentityJson());
    }

    /**
     * Task 18: what {@link #callback} redeems, with the account decision the response endpoint stored
     * ({@link VerifiedIdentityJson#readLogin}); the broker hands it to {@link WalletLoginCompleter}. Same checks and
     * refusals as {@link #callback}.
     */
    public VerifiedIdentityJson.StoredLogin redeem(final CallbackContext context) {
        final WalletTransaction tx = redeemTransaction(context);
        return VerifiedIdentityJson.readLogin(config.alias(), tx.verifiedIdentityJson());
    }

    private WalletTransaction redeemTransaction(final CallbackContext context) {
        final String code = context.parameters() == null ? null : context.parameters().get(RESPONSE_CODE_PARAM);
        if (blank(code)) {
            throw refused(WalletErrorCode.INVALID_RESPONSE, "the callback has no response_code", null);
        }
        if (blank(context.expectedState())) {
            throw refused(WalletErrorCode.STATE_MISMATCH, "no wallet login is pending in this session", null);
        }
        if (blank(context.browserBindingHash())) {
            throw refused(WalletErrorCode.BROWSER_MISMATCH, "this browser holds no wallet login binding", null);
        }
        final WalletTransaction tx = transactions.redeem(code, context.expectedState(), context.browserBindingHash())
                .orElseThrow(() -> refused(WalletErrorCode.REPLAY,
                        "response code unknown, expired, already used, or not this login's state and browser", null));
        if (!config.alias().equals(tx.providerAlias()) || !Objects.equals(tx.realmId(), context.realmId())) {
            throw refused(WalletErrorCode.INVALID_RESPONSE, "the transaction belongs to another provider or realm",
                    tx.transactionId());
        }
        LOG.info("Wallet login redeemed: alias={} realm={} tx={}", LogSafe.sanitize(config.alias()),
                LogSafe.sanitize(tx.realmId()), tx.transactionId());
        return tx;
    }

    private WalletVerificationException refused(final WalletErrorCode code, final String safeDetail,
                                                final String transactionId) {
        // DEBUG only: the broker logs the refusal once, at WARN, with its reason
        LOG.debug("Wallet callback refused: alias={} tx={} reason={}", LogSafe.sanitize(config.alias()),
                transactionId == null ? "-" : transactionId, code.reason());
        return new WalletVerificationException(code, safeDetail);
    }

    /** No-op: a wallet presentation leaves no upstream session. */
    @Override
    public void logout(final LogoutContext context) {
        // nothing to end at the wallet
    }

    // ------------------------------------------------------------------------------------------------ Task 18 view

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

    public TrustAnchors trustAnchors() {
        return trustAnchors;
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
                Duration.ofSeconds(config.clockSkewSeconds()), trustAnchors, statusPolicy,
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
