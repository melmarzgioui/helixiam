package io.helixiam.common.security;

import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

/**
 * Vendored from group.mfnr.subscriber.starter.security.utils.SecurityContext (starter-security
 * module). Not in the Task 1 file list; pulled in transitively because Task 2 folded
 * group.mfnr.authorization.service.TenantService, which reads the calling user's id off the
 * request's Spring Security {@code Authentication}. Verbatim (no AMQP/broker dependency in the
 * original — plain Spring Security API).
 */
public final class SecurityContext {

    private SecurityContext() {
        throw new IllegalAccessError();
    }

    private static Authentication getAuthenticatedUser() {
        if (SecurityContextHolder.getContext() == null || SecurityContextHolder.getContext().getAuthentication() == null || SecurityContextHolder.getContext().getAuthentication() instanceof AnonymousAuthenticationToken) {
            return null;
        }

        return SecurityContextHolder.getContext().getAuthentication();
    }

    public static String getUserId() {
        final Authentication authentication = getAuthenticatedUser();
        if (authentication == null) {
            return null;
        }
        return authentication.getName();
    }

    public static String getJwtToken() {
        final Authentication authentication = getAuthenticatedUser();

        if (!(authentication instanceof JwtAuthenticationToken jwtAuthenticationToken)) {
            return null;
        }

        return jwtAuthenticationToken.getToken().getTokenValue();
    }
}
