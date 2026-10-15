/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.wallet;

import io.helixiam.authorization.federation.wallet.dcql.DcqlQueryBuilder;
import io.helixiam.authorization.federation.wallet.mdoc.MdocPresentationVerifier;
import io.helixiam.authorization.federation.wallet.sdjwt.SdJwtVcPresentationVerifier;
import io.helixiam.authorization.federation.wallet.status.StatusListCache;
import io.helixiam.authorization.federation.wallet.status.StatusPolicy;
import io.helixiam.authorization.federation.wallet.status.TokenStatusListClient;
import io.helixiam.authorization.federation.wallet.transaction.WalletTransactionStore;
import io.helixiam.authorization.federation.wallet.trust.IssuerRevocationClient;
import io.helixiam.authorization.federation.wallet.trust.IssuerTrustValidator;
import io.helixiam.authorization.federation.wallet.trust.TrustAnchors;
import io.helixiam.authorization.security.audit.AuditLog;
import io.helixiam.authorization.service.key.RealmSigningKeys;
import io.helixiam.authorization.service.key.SigningKeyHandle;
import io.helixiam.authorization.service.key.SoftwareRealmSigningKeys;
import io.helixiam.common.net.OutboundUrlGuard;
import io.helixiam.authorization.federation.wallet.trust.tl.TrustedListAnchorSource;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.function.Supplier;

/**
 * Builds {@link WalletIdentityProvider}s for {@code FederationProviderFactory}: the wallet collaborators (validator,
 * realm signing keys, the transaction store bean, outbound guard, audit log) in one place.
 *
 * <p>{@link #build}: resolves the signing key <em>once</em> ({@code accessKeyRef} in the given realm, or, for the
 * dev-only {@code accessCertificatePrivateKey}, a restricted handle over that key and the configured chain), then runs
 * {@link WalletConfigValidator#requireValid(String, WalletProviderConfig, SigningKeyHandle)} on that same handle, so
 * the leaf whose SAN and validity were checked is the leaf that signs. An invalid config throws
 * {@link IllegalArgumentException} naming every field; the factory's callers log it and skip the provider. Then one
 * {@link TokenStatusListClient} per provider, with its {@link StatusPolicy} (the instance also put in its
 * {@link VerificationContext}) and {@link TokenStatusListClient#auditLogSink}, and one verifier per configured format
 * with the provider's limits (the mdoc verifier on {@link TokenStatusListClient#cwtEvaluator()}).
 *
 * <p>Realm of the key: a stored provider's own realm; a YAML provider ({@code helix.federation.wallet[*]}) resolves
 * in {@link #YAML_REALM} (ruling: its key must be imported in master).
 */
@Component
public class WalletIdentityProviders {

    /** The realm a YAML-configured wallet provider's {@code accessKeyRef} is resolved in. */
    public static final String YAML_REALM = "master";

    private final WalletConfigValidator validator;
    private final RealmSigningKeys keys;
    private final WalletTransactionStore transactions;
    private final OutboundUrlGuard guard;
    private final TokenStatusListClient.AuditSink auditSink;
    private final Clock clock;
    /** Task 22: the built provider's own audit log (WALLET_LOGIN_SUCCESS/FAILURE), distinct from {@link #auditSink}. */
    private final AuditLog auditLog;
    /** Issuer CRL / OCSP fetching and cache, shared by every provider this factory builds. */
    private final IssuerRevocationClient revocation;
    /** Verified Token Status Lists, shared by every provider this factory builds (one byte budget). */
    private final StatusListCache statusCache;
    /** Anchors from the realm's trusted list sources ({@code trustedLists.sources}); NONE without the service. */
    private final TrustedListAnchorSource trustedLists;

    /** Default revocation settings ({@link IssuerRevocationClient.Settings#DEFAULTS}). */
    public WalletIdentityProviders(final WalletConfigValidator validator, final RealmSigningKeys keys,
                                   final WalletTransactionStore transactions, final OutboundUrlGuard guard,
                                   final AuditLog auditLog) {
        this(validator, keys, transactions, guard, WalletStatusAudit.sink(auditLog), Clock.systemUTC(),
                auditLog);
    }

    /**
     * Production bean: the issuer-revocation client (one cache and byte budget shared by every wallet provider) from
     * {@code helix.wallet.revocation.max-crl-bytes} (default 10 MB), {@code .cache-max-entries} (default 256) and
     * {@code .cache-max-bytes} (default 32 MB); and the Token Status List cache, also shared, from
     * {@code helix.wallet.status-list.cache-max-entries} (default 64) and {@code .cache-max-bytes} (default 32 MB of
     * decoded lists). Concurrent wallet fetches are capped by the WALLET group of
     * {@link io.helixiam.common.net.OutboundFetchLimits}.
     */
    @Autowired
    public WalletIdentityProviders(final WalletConfigValidator validator, final RealmSigningKeys keys,
                                   final WalletTransactionStore transactions, final OutboundUrlGuard guard,
                                   final AuditLog auditLog,
                                   @Value("${helix.wallet.revocation.max-crl-bytes:"
                                           + IssuerRevocationClient.Settings.DEFAULT_MAX_CRL_BYTES + "}")
                                   final long maxCrlBytes,
                                   @Value("${helix.wallet.revocation.cache-max-entries:"
                                           + IssuerRevocationClient.Settings.DEFAULT_CACHE_MAX_ENTRIES + "}")
                                   final int revocationCacheEntries,
                                   @Value("${helix.wallet.revocation.cache-max-bytes:"
                                           + IssuerRevocationClient.Settings.DEFAULT_CACHE_MAX_BYTES + "}")
                                   final long revocationCacheBytes,
                                   @Value("${helix.wallet.status-list.cache-max-entries:"
                                           + StatusListCache.DEFAULT_MAX_ENTRIES + "}")
                                   final int statusCacheEntries,
                                   @Value("${helix.wallet.status-list.cache-max-bytes:"
                                           + StatusListCache.DEFAULT_MAX_BYTES + "}")
                                   final long statusCacheBytes,
                                   final ObjectProvider<TrustedListAnchorSource> trustedLists) {
        this(validator, keys, transactions, guard, TokenStatusListClient.auditLogSink(auditLog), Clock.systemUTC(),
                auditLog, new IssuerRevocationClient(guard,
                        new IssuerRevocationClient.Settings(maxCrlBytes, revocationCacheEntries, revocationCacheBytes),
                        Clock.systemUTC()), new StatusListCache(statusCacheEntries, statusCacheBytes),
                trustedLists.getIfAvailable(() -> TrustedListAnchorSource.NONE));
    }

    WalletIdentityProviders(final WalletConfigValidator validator, final RealmSigningKeys keys,
                            final WalletTransactionStore transactions, final OutboundUrlGuard guard,
                            final TokenStatusListClient.AuditSink auditSink, final Clock clock,
                            final AuditLog auditLog) {
        this(validator, keys, transactions, guard, auditSink, clock, auditLog, new IssuerRevocationClient(guard,
                IssuerRevocationClient.Settings.DEFAULTS, Clock.systemUTC()), new StatusListCache());
    }

    WalletIdentityProviders(final WalletConfigValidator validator, final RealmSigningKeys keys,
                            final WalletTransactionStore transactions, final OutboundUrlGuard guard,
                            final TokenStatusListClient.AuditSink auditSink, final Clock clock,
                            final AuditLog auditLog, final IssuerRevocationClient revocation,
                            final StatusListCache statusCache) {
        this(validator, keys, transactions, guard, auditSink, clock, auditLog, revocation, statusCache,
                TrustedListAnchorSource.NONE);
    }

    WalletIdentityProviders(final WalletConfigValidator validator, final RealmSigningKeys keys,
                            final WalletTransactionStore transactions, final OutboundUrlGuard guard,
                            final TokenStatusListClient.AuditSink auditSink, final Clock clock,
                            final AuditLog auditLog, final IssuerRevocationClient revocation,
                            final StatusListCache statusCache, final TrustedListAnchorSource trustedLists) {
        this.trustedLists = Objects.requireNonNull(trustedLists, "trustedLists");
        this.revocation = Objects.requireNonNull(revocation, "revocation");
        this.statusCache = Objects.requireNonNull(statusCache, "statusCache");
        this.validator = Objects.requireNonNull(validator, "validator");
        this.keys = Objects.requireNonNull(keys, "keys");
        this.transactions = Objects.requireNonNull(transactions, "transactions");
        this.guard = Objects.requireNonNull(guard, "guard");
        this.auditSink = Objects.requireNonNull(auditSink, "auditSink");
        this.clock = Objects.requireNonNull(clock, "clock");
        this.auditLog = Objects.requireNonNull(auditLog, "auditLog");
    }

    /** The same factory reading trusted list anchors from {@code lists} (tests and wiring without Spring). */
    public WalletIdentityProviders withTrustedLists(final TrustedListAnchorSource lists) {
        return new WalletIdentityProviders(validator, keys, transactions, guard, auditSink, clock, auditLog, revocation,
                statusCache, lists);
    }

    /**
     * A validated STORED provider of {@code realmId}: its key lives there, and it starts logins only there.
     *
     * @throws IllegalArgumentException when the config is invalid (the message names each field, never key material)
     */
    public WalletIdentityProvider build(final String realmId, final WalletProviderConfig config) {
        return build(realmId, realmId, config);
    }

    /**
     * A validated YAML provider ({@code helix.federation.wallet[*]}): its key lives in {@link #YAML_REALM}, and it serves
     * every realm.
     *
     * @throws IllegalArgumentException when the config is invalid
     */
    public WalletIdentityProvider buildFromYaml(final WalletProviderConfig config) {
        return build(YAML_REALM, null, config);
    }

    private WalletIdentityProvider build(final String realmId, final String keyRealm,
                                         final WalletProviderConfig config) {
        final SigningKeyHandle signingKey = signingKey(realmId, config);
        validator.requireValid(realmId, config, signingKey);
        if (signingKey == null) { // valid on a second resolve that the first one missed: refuse, never sign unchecked
            throw new IllegalArgumentException("Wallet provider '" + config.alias()
                    + "' is invalid: accessKeyRef: The key behind accessKeyRef cannot be used");
        }
        final Supplier<TrustAnchors> anchors = anchors(realmId, config);
        final StatusPolicy statusPolicy = config.statusList().toStatusPolicy();
        final IssuerTrustValidator trust = new IssuerTrustValidator(revocation);
        final TokenStatusListClient statusClient = new TokenStatusListClient(statusPolicy, trust, guard, auditSink,
                statusCache);
        final WalletProviderConfig.Limits limits = config.limits();
        final Map<String, PresentationVerifier> verifiers = new LinkedHashMap<>();
        for (final String format : config.credentialFormats()) {
            if (DcqlQueryBuilder.SD_JWT_FORMAT.equals(format)) {
                verifiers.put(format, new SdJwtVcPresentationVerifier(trust, statusClient,
                        SdJwtVcPresentationVerifier.DEFAULT_KB_MAX_AGE, SdJwtVcPresentationVerifier.DEFAULT_MAX_DISCLOSURES,
                        limits.maxJwtBytes()));
            } else if (DcqlQueryBuilder.MDOC_FORMAT.equals(format)) {
                verifiers.put(format, new MdocPresentationVerifier(trust, statusClient.cwtEvaluator(),
                        limits.maxJwtBytes(), limits.cborLimits()));
            }
        }
        return new WalletIdentityProvider(config, keyRealm, signingKey, anchors, statusPolicy, statusClient, verifiers,
                transactions, clock, auditLog);
    }

    /**
     * The provider's issuer trust: the pasted PEM anchors (fixed), plus, when {@code trustedLists.sources} is set, the
     * realm's current trusted-list anchors read at every call, so a refresh, withdrawal or expiry applies at once.
     */
    private Supplier<TrustAnchors> anchors(final String realm, final WalletProviderConfig config) {
        final boolean pasted = config.trustAnchors() != null && !config.trustAnchors().isBlank();
        final TrustAnchors fixed = pasted ? TrustAnchors.fromPem(config.trustAnchors(), null,
                config.revocationChecking()) : new TrustAnchors(Set.of(), List.of(), config.revocationChecking());
        final WalletProviderConfig.TrustedLists lists = config.trustedLists();
        if (lists.isEmpty()) {
            return () -> fixed;
        }
        return () -> {
            final Set<TrustAnchor> all = new LinkedHashSet<>(fixed.anchors());
            for (final X509Certificate cert : trustedLists.anchors(realm, lists.sources(), lists.serviceTypes())) {
                if (all.stream().noneMatch(a -> cert.equals(a.getTrustedCert()))) {
                    all.add(new TrustAnchor(cert, null));
                }
            }
            return new TrustAnchors(all, fixed.pinnedIntermediates(), fixed.revocation());
        };
    }

    /**
     * The one handle the provider signs with, or null when it cannot be had (the validator then reports why): the
     * dev PEM over the configured chain, else {@code accessKeyRef} resolved in {@code realmId}.
     */
    private SigningKeyHandle signingKey(final String realmId, final WalletProviderConfig config) {
        try {
            if (config.accessCertificatePrivateKey() != null && !config.accessCertificatePrivateKey().isBlank()) {
                return config.accessCertificateChain() == null ? null : SoftwareRealmSigningKeys.softwareHandle(
                        "dev-pem:" + config.alias(), config.accessCertificatePrivateKey(),
                        config.accessCertificateChain());
            }
            return config.accessKeyRef() == null || config.accessKeyRef().isBlank() ? null
                    : keys.resolve(realmId, config.accessKeyRef());
        } catch (final RuntimeException e) {
            return null;
        }
    }
}
