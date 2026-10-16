/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.security;

import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.jwt.JwtEncodingException;

import java.util.function.Supplier;

/**
 * The realm's ACTIVE key decides the JWS {@code alg} of everything the realm signs (bring-your-own keys, D27).
 *
 * <p>Wraps the single {@link JwtEncoder} every signing path uses — Spring Authorization Server's token generator (ID
 * tokens, JWT access tokens), back-channel {@code logout_token}s, RFC 8693 delegation tokens, workload-identity tokens
 * and JARM responses. A requested algorithm that the ACTIVE key cannot produce (RS256 asked, EC key active; ES256
 * asked, RSA key active) is replaced by the ACTIVE key's algorithm. PS256 on an RSA realm stays PS256.
 */
public final class RealmAlgorithmJwtEncoder implements JwtEncoder {

    private final JwtEncoder delegate;
    private final Supplier<String> activeAlgorithm;

    public RealmAlgorithmJwtEncoder(final JwtEncoder delegate, final Supplier<String> activeAlgorithm) {
        this.delegate = delegate;
        this.activeAlgorithm = activeAlgorithm;
    }

    @Override
    public Jwt encode(final JwtEncoderParameters parameters) throws JwtEncodingException {
        final String active = activeAlgorithm.get();
        if (active == null) {
            return delegate.encode(parameters);
        }
        final JwsHeader header = parameters.getJwsHeader();
        final String requested = header == null || header.getAlgorithm() == null
                ? "RS256" : header.getAlgorithm().getName();
        if (fits(requested, active)) {
            return delegate.encode(parameters);
        }
        final JwsHeader adjusted = header == null
                ? JwsHeader.with(SignatureAlgorithm.from(active)).build()
                : JwsHeader.from(header).algorithm(SignatureAlgorithm.from(active)).build();
        return delegate.encode(JwtEncoderParameters.from(adjusted, parameters.getClaims()));
    }

    /** Whether a key of the {@code active} algorithm's type can sign {@code requested}. */
    static boolean fits(final String requested, final String active) {
        final boolean activeEc = active.startsWith("ES");
        final boolean requestedEc = requested.startsWith("ES");
        if (activeEc) {
            return requested.equals(active); // one curve: P-256 signs ES256 only
        }
        return !requestedEc && (requested.startsWith("RS") || requested.startsWith("PS"))
                && (requested.equals("RS256") || requested.equals("PS256"));
    }
}
