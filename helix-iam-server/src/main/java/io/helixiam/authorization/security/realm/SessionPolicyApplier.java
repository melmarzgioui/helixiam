package io.helixiam.authorization.security.realm;

import io.helixiam.authorization.amqp.realm.RealmSettingsDto;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.stereotype.Component;

/**
 * Helix IAM SSO P3: stamps the realm's SSO session policy onto the just-authenticated HTTP session.
 *
 * <p>The session's {@code MAX_INACTIVE_INTERVAL} becomes the realm's idle timeout (per-session, so realms
 * with different idle timeouts coexist in the shared Spring Session store). When the realm enables
 * remember-me and the user opted in (a truthy {@code remember-me} login parameter), the longer remember-me
 * lifetime is used instead. The hard max-lifetime is enforced separately at the authorize endpoint
 * ({@link io.helixiam.authorization.security.oidc.PromptAndMaxAgeAuthorizeFilter}).
 */
@Component
public class SessionPolicyApplier {

    private final RealmSettingsResolver resolver;

    public SessionPolicyApplier(final RealmSettingsResolver resolver) {
        this.resolver = resolver;
    }

    /** Apply the realm's idle (or remember-me) lifetime to the current session. Never throws. */
    public void applyOnLogin(final HttpServletRequest request, final String realmId) {
        try {
            final RealmSettingsDto settings = resolver.get(realmId);
            final boolean remembered = settings.rememberMe() && isTruthy(request.getParameter("remember-me"));
            final int interval = remembered ? settings.rememberMeLifetimeSeconds() : settings.ssoSessionIdleTimeoutSeconds();
            request.getSession(true).setMaxInactiveInterval(interval);
        } catch (final RuntimeException e) {
            // Never let session-policy application break login.
        }
    }

    private static boolean isTruthy(final String value) {
        return value != null && (value.equalsIgnoreCase("on") || value.equalsIgnoreCase("true") || value.equals("1"));
    }
}
