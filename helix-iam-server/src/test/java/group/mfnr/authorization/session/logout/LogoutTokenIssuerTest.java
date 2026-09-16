package group.mfnr.authorization.session.logout;

import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;

import java.time.Instant;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Helix IAM SSO P6: the OIDC back-channel {@code logout_token} (RFC: OpenID Connect Back-Channel Logout).
 * Must carry {@code iss/aud/sub/iat/jti} + the {@code events} URN claim and {@code sid} when known, and
 * must NOT carry a {@code nonce}.
 */
class LogoutTokenIssuerTest {

    private static final String EVENTS_URN = "http://schemas.openid.net/event/backchannel-logout";

    private final JwtEncoder jwtEncoder = mock(JwtEncoder.class);
    private final LogoutTokenIssuer issuer = new LogoutTokenIssuer(jwtEncoder);

    @SuppressWarnings("unchecked")
    @Test
    void issue_buildsACompliantLogoutToken() {
        final Jwt jwt = mock(Jwt.class);
        when(jwt.getTokenValue()).thenReturn("signed.logout.token");
        when(jwtEncoder.encode(any())).thenReturn(jwt);

        final String token = issuer.issue("https://idp/realms/master", "spa-app", "user-1", "sid-abc");

        assertEquals("signed.logout.token", token);
        final ArgumentCaptor<JwtEncoderParameters> captor = ArgumentCaptor.forClass(JwtEncoderParameters.class);
        verify(jwtEncoder).encode(captor.capture());
        final Map<String, Object> claims = captor.getValue().getClaims().getClaims();

        assertEquals("https://idp/realms/master", claims.get("iss").toString());
        assertEquals("user-1", claims.get("sub"));
        assertEquals("sid-abc", claims.get("sid"));
        assertTrue(claims.get("aud").toString().contains("spa-app"));
        assertNotNull(claims.get("jti"));
        assertNotNull(claims.get("iat"));
        assertFalse(claims.containsKey("nonce"), "a logout_token must never carry a nonce");
        final Map<String, Object> events = (Map<String, Object>) claims.get("events");
        assertTrue(events.containsKey(EVENTS_URN), "events must contain the back-channel-logout URN");
    }

    @Test
    void issue_omitsSid_whenNull() {
        final Jwt jwt = mock(Jwt.class);
        when(jwt.getTokenValue()).thenReturn("t");
        when(jwtEncoder.encode(any())).thenReturn(jwt);

        issuer.issue("https://idp/realms/master", "spa-app", "user-1", null);

        final ArgumentCaptor<JwtEncoderParameters> captor = ArgumentCaptor.forClass(JwtEncoderParameters.class);
        verify(jwtEncoder).encode(captor.capture());
        assertFalse(captor.getValue().getClaims().getClaims().containsKey("sid"));
    }
}
