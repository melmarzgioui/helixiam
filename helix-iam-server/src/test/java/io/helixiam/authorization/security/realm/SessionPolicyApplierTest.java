package io.helixiam.authorization.security.realm;

import io.helixiam.authorization.amqp.realm.RealmSettingsDto;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import org.junit.jupiter.api.Test;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Helix IAM SSO P3: applies the realm's SSO session policy to the just-authenticated session — the idle
 * timeout normally, the longer remember-me lifetime when the realm allows it and the user opted in.
 */
class SessionPolicyApplierTest {

    private final RealmSettingsResolver resolver = mock(RealmSettingsResolver.class);
    private final SessionPolicyApplier applier = new SessionPolicyApplier(resolver);
    private final HttpServletRequest request = mock(HttpServletRequest.class);
    private final HttpSession session = mock(HttpSession.class);

    private RealmSettingsDto settings(final int idle, final boolean rememberMe, final int rememberLifetime) {
        return new RealmSettingsDto("gov", "gov", null, 3600, 5_184_000, false, false, 12, true,
                idle, 36_000, rememberMe, rememberLifetime,
                false, 5, 900, 900, false,
                false, false, false, false, false, 0,
                false, "none", null, null, 0, true, false, 40, 70, "allow", "step_up", "deny",
                null, null, null, null, null, true);
    }

    @Test
    void appliesIdleTimeout_byDefault() {
        when(resolver.get("gov")).thenReturn(settings(600, false, 999_999));
        when(request.getSession(true)).thenReturn(session);
        when(request.getParameter("remember-me")).thenReturn(null);

        applier.applyOnLogin(request, "gov");

        verify(session).setMaxInactiveInterval(600);
    }

    @Test
    void appliesRememberMeLifetime_whenRealmAllowsItAndUserOptedIn() {
        when(resolver.get("gov")).thenReturn(settings(600, true, 1_209_600));
        when(request.getSession(true)).thenReturn(session);
        when(request.getParameter("remember-me")).thenReturn("on");

        applier.applyOnLogin(request, "gov");

        verify(session).setMaxInactiveInterval(1_209_600);
    }

    @Test
    void ignoresRememberMe_whenRealmDisallowsIt() {
        when(resolver.get("gov")).thenReturn(settings(600, false, 1_209_600));
        when(request.getSession(true)).thenReturn(session);
        when(request.getParameter("remember-me")).thenReturn("on");

        applier.applyOnLogin(request, "gov");

        verify(session).setMaxInactiveInterval(600); // realm rememberMe=false → idle wins
    }
}
