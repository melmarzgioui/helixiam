package io.helixiam.authorization.security.session;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Helix IAM SSO P2: stamps the moment the session became fully authenticated ({@code auth_time}) so the
 * authorize endpoint can enforce {@code max_age}/{@code prompt} (and the id_token can carry {@code auth_time}).
 */
class AuthTimeStamperTest {

    private static final long NOW = 1_782_600_000L;
    private final AuthTimeStamper stamper = new AuthTimeStamper(() -> NOW);

    @Test
    void stamp_writesEpochSecondsToTheSession() {
        final HttpServletRequest request = mock(HttpServletRequest.class);
        final HttpSession session = mock(HttpSession.class);
        when(request.getSession(true)).thenReturn(session);

        stamper.stamp(request);

        verify(session).setAttribute(AuthTimeStamper.HELIX_AUTH_TIME, NOW);
    }

    @Test
    void read_returnsTheStampedValue() {
        final HttpServletRequest request = mock(HttpServletRequest.class);
        final HttpSession session = mock(HttpSession.class);
        when(request.getSession(false)).thenReturn(session);
        when(session.getAttribute(AuthTimeStamper.HELIX_AUTH_TIME)).thenReturn(NOW);

        assertEquals(NOW, stamper.read(request));
    }

    @Test
    void read_returnsNull_whenThereIsNoSession() {
        final HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getSession(false)).thenReturn(null);

        assertNull(stamper.read(request));
    }
}
