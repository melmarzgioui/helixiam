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
 * {@code aud}=clientId, {@code sub}, {@code iat}, a short {@code exp}, a unique {@code jti}, the
 * back-channel-logout {@code events} URN, and {@code sid} when known — and explicitly NO {@code nonce}.
 * Relying parties should reject a {@code jti} they have already seen until its {@code exp} (A9).
 */
@Component
public class LogoutTokenIssuer {

    /** The OIDC Back-Channel Logout event URN that marks a JWT as a logout_token. */
    public static final String BACKCHANNEL_LOGOUT_EVENT = "http://schemas.openid.net/event/backchannel-logout";

    /** Default lifetime of a logout_token in seconds (A9): long enough for delivery, short against replay. */
    public static final long DEFAULT_TTL_SECONDS = 120;

    private final JwtEncoder jwtEncoder;
    private final long ttlSeconds;

    public LogoutTokenIssuer(final JwtEncoder jwtEncoder) {
        this(jwtEncoder, DEFAULT_TTL_SECONDS);
    }

    /** {@code ttlSeconds}: the logout_token lifetime ({@code helix.oidc.logout-token-ttl-seconds}, 1..600). */
    @org.springframework.beans.factory.annotation.Autowired
    public LogoutTokenIssuer(final JwtEncoder jwtEncoder,
                             @org.springframework.beans.factory.annotation.Value(
                                     "${helix.oidc.logout-token-ttl-seconds:" + DEFAULT_TTL_SECONDS + "}")
                             final long ttlSeconds) {
        this.jwtEncoder = jwtEncoder;
        this.ttlSeconds = Math.max(1, Math.min(600, ttlSeconds));
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
        final Instant now = Instant.now();
        final Map<String, Object> events = new LinkedHashMap<>();
        events.put(BACKCHANNEL_LOGOUT_EVENT, new LinkedHashMap<>());

        final JwtClaimsSet.Builder claims = JwtClaimsSet.builder()
                .issuer(issuer)
                .subject(subject)
                .audience(List.of(clientId))
                .issuedAt(now)
                // A9: short-lived and one jti per token (random, never reused), so an RP can reject a replay.
                .expiresAt(now.plusSeconds(ttlSeconds))
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
