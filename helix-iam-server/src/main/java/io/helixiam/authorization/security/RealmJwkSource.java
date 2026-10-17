/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.security;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import io.helixiam.authorization.amqp.ServiceProviderPublisher;
import io.helixiam.authorization.security.realm.RealmContextHolder;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Helix IAM E1.4: JWKSource backed by the realm key store.
 *
 * <p>Publishes the realm's ACTIVE key (signs new tokens), its PENDING keys (staged: published so relying parties pick
 * them up before they sign) and its ROTATED keys (verify tokens issued before the last rotation) — giving
 * zero-downtime rollover. Keys with a certificate chain carry {@code x5c} and {@code x5t#S256}. The key set is
 * refreshed from the store on a short TTL so a rotation propagates without a restart.
 *
 * <p>Spring's {@code NimbusJwtEncoder} rejects a JWKSource that returns more than one key
 * for a signing selection, so for a <i>signing</i> selection (the matcher is constrained by
 * key-type/algorithm) we return only the ACTIVE key (the one holding a private key); for the
 * unconstrained JWKS-publish selection we return every key. The {@code kid} is derived from
 * the key modulus, identical to the prior single-key source, so existing tokens keep verifying.
 */
public class RealmJwkSource implements JWKSource<SecurityContext> {

    private static final Logger LOG = LogManager.getLogger(RealmJwkSource.class);
    private static final long REFRESH_TTL_MS = 30_000L;

    private static final String DEFAULT_REALM = "master";

    private final ServiceProviderPublisher serviceProviderPublisher;

    /** Per-realm key cache (MT-3): each realm signs with / publishes its own keys, so they must not share a slot. */
    private final ConcurrentHashMap<String, CachedSet> byRealm = new ConcurrentHashMap<>();

    private record CachedSet(JWKSet set, long fetchedAtMs) {
    }

    public RealmJwkSource(final ServiceProviderPublisher serviceProviderPublisher) {
        this.serviceProviderPublisher = serviceProviderPublisher;
    }

    @Override
    public List<JWK> get(final com.nimbusds.jose.jwk.JWKSelector selector, final SecurityContext context) {
        return select(current(), selector);
    }

    /**
     * Selection over a fixed set. A <i>signing</i> selection (the matcher is constrained by key type or algorithm)
     * that matches several keys returns only the ones holding a private key — the ACTIVE key of that family; an
     * unconstrained selection (the JWKS publish) returns every key.
     */
    static List<JWK> select(final JWKSet set, final com.nimbusds.jose.jwk.JWKSelector selector) {
        if (set == null) {
            return List.of();
        }
        final List<JWK> selected = selector.select(set);
        final boolean signingSelection =
                (selector.getMatcher().getKeyTypes() != null && !selector.getMatcher().getKeyTypes().isEmpty())
                        || (selector.getMatcher().getAlgorithms() != null && !selector.getMatcher().getAlgorithms().isEmpty());
        if (signingSelection && selected.size() > 1) {
            final List<JWK> withPrivate = new ArrayList<>();
            for (final JWK jwk : selected) {
                if (jwk.isPrivate()) {
                    withPrivate.add(jwk);
                }
            }
            if (!withPrivate.isEmpty()) {
                return withPrivate; // sign with the ACTIVE key only
            }
        }
        return selected;
    }

    /** The current realm's key set, fetched once — for an encoder that must not see the cache change mid-encode. */
    public JWKSet snapshot() {
        return current();
    }

    /** A JWK source over a fixed snapshot, with this source's selection rules. */
    public static JWKSource<SecurityContext> fixed(final JWKSet snapshot) {
        return (selector, context) -> select(snapshot, selector);
    }

    /** The JWS algorithms the ACTIVE (private) keys of {@code set} can sign: RS256 + PS256 (RSA), ES256 (EC). */
    public static java.util.Set<String> signingAlgorithms(final JWKSet set) {
        final java.util.Set<String> algs = new java.util.LinkedHashSet<>();
        if (set != null) {
            for (final JWK jwk : set.getKeys()) {
                if (jwk.isPrivate() && jwk.getAlgorithm() != null) {
                    algs.add(jwk.getAlgorithm().getName());
                }
            }
        }
        return algs;
    }

    private JWKSet current() {
        // The realm of the in-flight request (token mint or JWKS publish); null outside a realm route.
        final String realm = RealmContextHolder.get() == null ? DEFAULT_REALM : RealmContextHolder.get();
        final long now = System.currentTimeMillis();
        final CachedSet existing = byRealm.get(realm);
        if (existing != null && now - existing.fetchedAtMs() <= REFRESH_TTL_MS) {
            return existing.set();
        }
        final JWKSet built = build(realm);
        if (built != null) {
            byRealm.put(realm, new CachedSet(built, now));
            return built;
        }
        return existing == null ? null : existing.set();
    }

    /**
     * Discovery's {@code id_token_signing_alg_values_supported}: exactly the algorithms of the realm's ACTIVE keys
     * (PENDING and ROTATED keys are excluded), RS256 first — OpenID Connect requires RS256, and every realm has an
     * ACTIVE RSA key.
     */
    public List<String> publishedAlgorithms() {
        final java.util.Set<String> active = signingAlgorithms(current());
        final List<String> out = new ArrayList<>();
        for (final String alg : List.of("RS256", "PS256", "ES256")) {
            if (active.contains(alg)) {
                out.add(alg);
            }
        }
        if (!out.contains("RS256")) {
            out.add(0, "RS256");
        }
        return out;
    }

    /** A realm's keys changed on this replica: drop its cached set so the change shows at once. */
    @org.springframework.context.event.EventListener
    public void onKeysChanged(final io.helixiam.authorization.service.key.RealmKeysChangedEvent event) {
        if (event.realmId() != null) {
            byRealm.remove(event.realmId());
        }
    }

    private JWKSet build(final String realm) {
        try {
            final List<io.helixiam.authorization.service.key.PublishedKey> published =
                    serviceProviderPublisher.retrievePublishedKeys(realm);
            if (published != null && !published.isEmpty()) {
                final List<JWK> keys = new ArrayList<>();
                for (final io.helixiam.authorization.service.key.PublishedKey key : published) {
                    addPublished(keys, key);
                }
                return new JWKSet(keys);
            }
            final List<JWK> keys = new ArrayList<>();

            final KeyPair active = serviceProviderPublisher.retrieveKeyPair(realm);
            if (active != null) {
                addAlgVariants(keys, (RSAPublicKey) active.getPublic(), (RSAPrivateKey) active.getPrivate());
            }

            try {
                final ArrayList<RSAPublicKey> rotated = serviceProviderPublisher.retrieveVerificationKeys(realm);
                if (rotated != null) {
                    for (final RSAPublicKey publicKey : rotated) {
                        addAlgVariants(keys, publicKey, null);
                    }
                }
            } catch (final Exception e) {
                // Verification (rotated) keys are best-effort; signing still works with the active key.
                LOG.warn("Could not load rotated verification keys: {}", e.getMessage());
            }

            return keys.isEmpty() ? null : new JWKSet(keys);
        } catch (final Exception e) {
            LOG.error("Failed to build JWK set", e);
            return null;
        }
    }

    /**
     * A2 (FAPI2): publish each RSA key twice — once for RS256 (the default, kid unchanged for
     * backward compatibility with tokens issued before this change) and once for PS256 (RSASSA-PSS,
     * required by FAPI2, which forbids RS256 for signatures). Both variants share the same underlying
     * RSA key material, so no new key material is needed; a Nimbus signing selection constrained to an
     * algorithm resolves to the matching variant (a JWK pinned to one alg won't match the other).
     */
    private void addAlgVariants(final List<JWK> keys, final RSAPublicKey publicKey,
                                final RSAPrivateKey privateKey) throws Exception {
        final String baseKid = kid(publicKey);
        keys.add(rsaKey(publicKey, privateKey, JWSAlgorithm.RS256, baseKid));
        keys.add(rsaKey(publicKey, privateKey, JWSAlgorithm.PS256, baseKid + "-ps256"));
    }

    /**
     * A published key as JWK(s): RSA → RS256 + PS256 twin, EC → ES256; each with {@code kid}, {@code alg},
     * {@code use: sig}, and — with a certificate chain — {@code x5c} (standard Base64 DER, without a trailing root) and
     * {@code x5t#S256}. Only the ACTIVE key carries its private part (so only it can be selected to sign).
     */
    private void addPublished(final List<JWK> keys, final io.helixiam.authorization.service.key.PublishedKey key)
            throws Exception {
        final java.security.PrivateKey priv = key.active() ? key.privateKey() : null;
        final List<com.nimbusds.jose.util.Base64> x5c = new ArrayList<>();
        com.nimbusds.jose.util.Base64URL x5t = null;
        if (key.chain() != null && !key.chain().isEmpty()) {
            for (final java.security.cert.X509Certificate cert
                    : io.helixiam.authorization.service.key.RealmKeyMaterial.x5cChain(key.chain())) {
                x5c.add(com.nimbusds.jose.util.Base64.encode(cert.getEncoded()));
            }
            x5t = com.nimbusds.jose.util.Base64URL.encode(
                    MessageDigest.getInstance("SHA-256").digest(key.chain().get(0).getEncoded()));
        }
        final String kid = io.helixiam.authorization.service.key.RealmKeyMaterial.kid(key.publicKey());
        if (key.publicKey() instanceof java.security.interfaces.ECPublicKey ec) {
            final com.nimbusds.jose.jwk.ECKey.Builder b = new com.nimbusds.jose.jwk.ECKey.Builder(
                    com.nimbusds.jose.jwk.Curve.P_256, ec).keyID(kid).keyUse(KeyUse.SIGNATURE)
                    .algorithm(JWSAlgorithm.ES256);
            if (priv != null) {
                b.privateKey(priv);
            }
            if (!x5c.isEmpty()) {
                b.x509CertChain(x5c).x509CertSHA256Thumbprint(x5t);
            }
            keys.add(b.build());
            return;
        }
        final RSAPublicKey rsa = (RSAPublicKey) key.publicKey();
        for (final JWSAlgorithm alg : List.of(JWSAlgorithm.RS256, JWSAlgorithm.PS256)) {
            final RSAKey.Builder b = new RSAKey.Builder(rsa)
                    .keyID(JWSAlgorithm.RS256.equals(alg) ? kid : kid + "-ps256")
                    .keyUse(KeyUse.SIGNATURE).algorithm(alg);
            if (priv != null) {
                b.privateKey(priv);
            }
            if (!x5c.isEmpty()) {
                b.x509CertChain(x5c).x509CertSHA256Thumbprint(x5t);
            }
            keys.add(b.build());
        }
    }

    private static String kid(final RSAPublicKey publicKey) throws Exception {
        final MessageDigest digest = MessageDigest.getInstance("SHA-256");
        return Base64.getEncoder().encodeToString(digest.digest(publicKey.getModulus().toByteArray()));
    }

    private RSAKey rsaKey(final RSAPublicKey publicKey, final RSAPrivateKey privateKey,
                          final JWSAlgorithm algorithm, final String kid) {
        final RSAKey.Builder builder = new RSAKey.Builder(publicKey)
                .keyID(kid)
                .keyUse(KeyUse.SIGNATURE)
                .algorithm(algorithm);
        if (privateKey != null) {
            builder.privateKey(privateKey);
        }
        return builder.build();
    }
}
