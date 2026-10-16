/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.security;

import com.nimbusds.jose.jwk.JWKSet;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.security.oauth2.jose.jws.JwsAlgorithm;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.jwt.JwtEncodingException;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;

import java.util.Set;
import java.util.function.Supplier;

/**
 * Chooses the JWS algorithm of everything a realm signs and signs it with the matching ACTIVE key (BYO keys,
 * security review round 1).
 *
 * <ul>
 *   <li>An explicit algorithm (an ID token's {@code id_token_signed_response_alg}, default RS256) is used when the
 *       realm has an ACTIVE key for it; otherwise RS256, with a WARN.</li>
 *   <li>{@link #REALM_DEFAULT} (access tokens, logout tokens, delegation and workload-identity tokens, JARM) is the
 *       realm's {@code signing.defaultAlg} (default RS256), with the same fallback.</li>
 * </ul>
 * The realm's key set is fetched <b>once per encode</b> and the token is signed against that snapshot, so a cache
 * refresh in the middle of an encode can never fail the request.
 */
public final class RealmAlgorithmJwtEncoder implements JwtEncoder {

    private static final Logger LOG = LogManager.getLogger(RealmAlgorithmJwtEncoder.class);

    /** "Use the realm's default signing algorithm" — set by callers that have no algorithm of their own. */
    public static final JwsAlgorithm REALM_DEFAULT = () -> "helix-realm-default";

    private final Supplier<JWKSet> snapshot;
    private final Supplier<String> realmDefault;
    private final JwtEncoder fallback;

    /**
     * @param snapshot     the current realm's key set (ACTIVE keys carry their private part)
     * @param realmDefault the current realm's default algorithm (null = RS256)
     * @param fallback     the encoder used when no key set can be loaded
     */
    public RealmAlgorithmJwtEncoder(final Supplier<JWKSet> snapshot, final Supplier<String> realmDefault,
                                    final JwtEncoder fallback) {
        this.snapshot = snapshot;
        this.realmDefault = realmDefault;
        this.fallback = fallback;
    }

    @Override
    public Jwt encode(final JwtEncoderParameters parameters) throws JwtEncodingException {
        final JWKSet set = snapshot.get();
        final JwsHeader header = parameters.getJwsHeader();
        String requested = header == null || header.getAlgorithm() == null ? "RS256" : header.getAlgorithm().getName();
        if (REALM_DEFAULT.getName().equals(requested)) {
            final String d = realmDefault.get();
            requested = d == null || d.isBlank() ? "RS256" : d;
        }
        final Set<String> available = RealmJwkSource.signingAlgorithms(set);
        String chosen = requested;
        if (!available.isEmpty() && !available.contains(requested)) {
            LOG.warn("No ACTIVE key for {} in this realm; signing with RS256 instead", requested);
            chosen = "RS256";
        }
        final SignatureAlgorithm alg = SignatureAlgorithm.from(chosen);
        final JwsHeader adjusted = header == null ? JwsHeader.with(alg).build() : JwsHeader.from(header).algorithm(alg).build();
        final JwtEncoder encoder = set == null ? fallback : new NimbusJwtEncoder(RealmJwkSource.fixed(set));
        return encoder.encode(JwtEncoderParameters.from(adjusted, parameters.getClaims()));
    }
}
