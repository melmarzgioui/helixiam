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
 * Helix IAM E1.4: JWKSource backed by the realm key store (via AMQP).
 *
 * <p>Publishes the realm's ACTIVE key (signs new tokens) plus its ROTATED keys (verify
 * tokens issued before the last rotation) — giving zero-downtime rotation. The key set is
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
        final JWKSet set = current();
        final List<JWK> selected = selector.select(set);

        final boolean signingSelection =
                (selector.getMatcher().getKeyTypes() != null && !selector.getMatcher().getKeyTypes().isEmpty())
                        || (selector.getMatcher().getAlgorithms() != null && !selector.getMatcher().getAlgorithms().isEmpty());

        if (signingSelection && selected.size() > 1) {
            final List<JWK> withPrivate = new ArrayList<>();
            for (final JWK jwk : selected) {
                if (jwk instanceof RSAKey rsaKey && rsaKey.isPrivate()) {
                    withPrivate.add(jwk);
                }
            }
            if (!withPrivate.isEmpty()) {
                return withPrivate; // sign with the ACTIVE key only
            }
        }
        return selected;
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

    private JWKSet build(final String realm) {
        try {
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
