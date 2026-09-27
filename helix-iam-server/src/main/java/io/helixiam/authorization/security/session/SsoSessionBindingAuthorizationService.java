/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.security.session;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

/**
 * A3: binds an authorization code to the browser SSO session that approved it. When the authorization endpoint
 * saves a freshly issued code (in the user's browser request), this copies the session's {@code sid} and
 * {@code auth_time} ({@link AuthTimeStamper}) into the authorization's attributes. They travel with the
 * authorization through the code exchange and every refresh, so the token customizer can put the SAME
 * {@code sid} and the time of the last INTERACTIVE login into every ID token (the token endpoint has no browser
 * session to read them from). Everything else is delegated unchanged.
 */
public class SsoSessionBindingAuthorizationService implements OAuth2AuthorizationService {

    /** Authorization attribute: the SSO session's OIDC {@code sid} (String). */
    public static final String SID_ATTRIBUTE = "helix.sid";
    /** Authorization attribute: epoch-second {@code auth_time} of the interactive login (Long). */
    public static final String AUTH_TIME_ATTRIBUTE = "helix.auth_time";

    private final OAuth2AuthorizationService delegate;
    private final AuthTimeStamper authTimeStamper = new AuthTimeStamper();

    public SsoSessionBindingAuthorizationService(final OAuth2AuthorizationService delegate) {
        this.delegate = delegate;
    }

    @Override
    public void save(final OAuth2Authorization authorization) {
        delegate.save(bindToSession(authorization));
    }

    @Override
    public void remove(final OAuth2Authorization authorization) {
        delegate.remove(authorization);
    }

    @Override
    public OAuth2Authorization findById(final String id) {
        return delegate.findById(id);
    }

    @Override
    public OAuth2Authorization findByToken(final String token, final OAuth2TokenType tokenType) {
        return delegate.findByToken(token, tokenType);
    }

    /** The wrapped store. */
    public OAuth2AuthorizationService delegate() {
        return delegate;
    }

    private OAuth2Authorization bindToSession(final OAuth2Authorization authorization) {
        if (authorization == null
                || authorization.getToken(OAuth2AuthorizationCode.class) == null
                || authorization.getAccessToken() != null
                || authorization.getAttribute(SID_ATTRIBUTE) != null) {
            return authorization; // only a code still being issued, and only once
        }
        final HttpServletRequest request = currentRequest();
        if (request == null) {
            return authorization;
        }
        final String sid = AuthTimeStamper.readSid(request);
        final Long authTime = authTimeStamper.read(request);
        if (sid == null && authTime == null) {
            return authorization;
        }
        final OAuth2Authorization.Builder builder = OAuth2Authorization.from(authorization);
        if (sid != null) {
            builder.attribute(SID_ATTRIBUTE, sid);
        }
        if (authTime != null) {
            builder.attribute(AUTH_TIME_ATTRIBUTE, authTime);
        }
        return builder.build();
    }

    private static HttpServletRequest currentRequest() {
        final RequestAttributes attributes = RequestContextHolder.getRequestAttributes();
        return attributes instanceof ServletRequestAttributes servlet ? servlet.getRequest() : null;
    }
}
