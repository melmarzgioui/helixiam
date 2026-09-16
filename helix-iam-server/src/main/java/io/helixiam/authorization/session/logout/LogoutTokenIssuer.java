package io.helixiam.authorization.session.logout;

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
 * with the realm's active key via the shared {@link JwtEncoder}). Per the spec it carries {@code iss},
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

    /** A signed logout_token for {@code clientId}'s back-channel endpoint. */
    public String issue(final String issuer, final String clientId, final String subject, final String sid) {
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
        return jwtEncoder.encode(JwtEncoderParameters.from(JwsHeader.with(() -> "RS256").build(), claims.build()))
                .getTokenValue();
    }
}
