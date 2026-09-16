package group.mfnr.authorization.session.logout;

import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtEncoder;

import java.util.List;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Helix IAM SSO P6: fans a signed logout_token out to each client's back-channel endpoint; best-effort —
 * one unreachable RP must not stop the others.
 */
class BackchannelLogoutNotifierTest {

    private final JwtEncoder jwtEncoder = mock(JwtEncoder.class);
    private final LogoutTokenIssuer issuer = new LogoutTokenIssuer(jwtEncoder);
    private final BackchannelLogoutNotifier.Poster poster = mock(BackchannelLogoutNotifier.Poster.class);
    private final BackchannelLogoutNotifier notifier = new BackchannelLogoutNotifier(issuer, poster);

    @Test
    void posts_aLogoutToken_toEveryTarget_evenWhenOneFails() {
        final Jwt jwt = mock(Jwt.class);
        when(jwt.getTokenValue()).thenReturn("logout.token");
        when(jwtEncoder.encode(any())).thenReturn(jwt);
        doThrow(new RuntimeException("rp down")).when(poster).post(eq("https://b/logout"), any());

        notifier.notifyClients("https://idp/realms/master", "user-1", "sid-1", List.of(
                new BackchannelLogoutNotifier.Target("a", "https://a/logout"),
                new BackchannelLogoutNotifier.Target("b", "https://b/logout"),
                new BackchannelLogoutNotifier.Target("c", "https://c/logout")));

        verify(poster).post("https://a/logout", "logout.token");
        verify(poster).post("https://b/logout", "logout.token"); // attempted, threw
        verify(poster).post("https://c/logout", "logout.token");
        verify(poster, times(3)).post(any(), any());
    }

    @Test
    void skipsTargets_withNoBackchannelUri() {
        final Jwt jwt = mock(Jwt.class);
        when(jwt.getTokenValue()).thenReturn("t");
        when(jwtEncoder.encode(any())).thenReturn(jwt);

        notifier.notifyClients("https://idp/realms/master", "user-1", "sid-1", List.of(
                new BackchannelLogoutNotifier.Target("a", null),
                new BackchannelLogoutNotifier.Target("b", "")));

        verify(poster, times(0)).post(any(), any());
    }
}
