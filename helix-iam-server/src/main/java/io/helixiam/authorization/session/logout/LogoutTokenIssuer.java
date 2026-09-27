/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.session.logout;

import io.helixiam.authorization.security.realm.RealmContextHolder;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * Helix IAM SSO P6: mints the OIDC Back-Channel Logout {@code logout_token} (a short JWT, RS256, signed
 * with the session realm's active key via the shared {@link JwtEncoder}). Per the spec it carries {@code iss},
 * {@code aud}=clientId, {@code sub}, {@code iat}, {@code jti}, the back-channel-logout {@code events} URN,
 * and {@code sid} when known — and explicitly NO {@code nonce}.
 */
@Component
public class LogoutTokenIssuer {

    /** The OIDC Back-Channel Logout event URN that marks a JWT as a logout_token. */
    public static final String BACKCHANNEL_LOGOUT_EVENT = "http://schemas.openid.net/event/backchannel-logout";

    private final JwtEncoder jwtEncoder;

    public LogoutTokenIssuer(final JwtEncoder jwtEncoder) {
        this.jwtEncoder = jwtEncoder;
    }

    /**
     * A signed logout_token for {@code clientId}'s back-channel endpoint, signed with {@code realm}'s active key.
     *
     * <p>A5: the signing key is chosen by {@link RealmContextHolder}, which is the realm of the in-flight request —
     * none at all for an {@code /admin/**} call (the key source then falls back to master). The token must be
     * signed by the realm the SESSION belongs to (the one whose JWKS the RP trusts), so that realm is bound for
     * the signing and the caller's context restored afterwards.
     */
    public String issue(final String realm, final String issuer, final String clientId, final String subject,
                        final String sid) {
        final Map<String, Object> events = new LinkedHashMap<>();
        events.put(BACKCHANNEL_LOGOUT_EVENT, new LinkedHashMap<>());

        final JwtClaimsSet.Builder claims = JwtClaimsSet.builder()
                .issuer(issuer)
                .subject(subject)
                .audience(List.of(clientId))
                .issuedAt(Instant.now())
                .id(UUID.randomUUID().toString())
                .claim("events", events);
        if (sid != null && !sid.isBlank()) {
            claims.claim("sid", sid);
        }
        final JwtEncoderParameters parameters = JwtEncoderParameters.from(JwsHeader.with(() -> "RS256").build(),
                claims.build());
        final String previousRealm = RealmContextHolder.get();
        try {
            if (realm != null && !realm.isBlank()) {
                RealmContextHolder.set(realm);
            }
            return jwtEncoder.encode(parameters).getTokenValue();
        } finally {
            if (previousRealm == null) {
                RealmContextHolder.clear();
            } else {
                RealmContextHolder.set(previousRealm);
            }
        }
    }
}
