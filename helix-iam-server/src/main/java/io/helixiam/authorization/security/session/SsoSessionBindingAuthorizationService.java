/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.security.session;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.time.Instant;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.Map;

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
    /** Authorization attribute: id of the browser (HTTP) session that approved the code (String). */
    public static final String HTTP_SESSION_ATTRIBUTE = "helix.http_session";
    /**
     * Authorization attribute: the brokered level of assurance of the login that approved the code
     * (String), when the session has one ({@link AuthTimeStamper#ACR_SESSION_ATTRIBUTE}) — Task 3.
     */
    public static final String ACR_ATTRIBUTE = "helix_acr";

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
        return withDateAuthTime(delegate.findById(id));
    }

    @Override
    public OAuth2Authorization findByToken(final String token, final OAuth2TokenType tokenType) {
        return withDateAuthTime(delegate.findByToken(token, tokenType));
    }

    /**
     * Spring Boot 4: Spring Security 7's {@code JwtGenerator} copies {@code auth_time} from the previous ID token on a
     * refresh and reads it as a {@link Date}. HelixIAM's ID tokens carry it as epoch seconds ({@link Long}, see
     * {@link IdTokenSessionClaims}), and so does every ID token 1.0 stored, so each ID-token refresh failed with a
     * {@code ClassCastException} (HTTP 500). The loaded authorization's stored ID token gets the same instant as a
     * {@link Date}, in memory only: the stored row is not rewritten, the token's metadata (claims) is unchanged, and
     * {@link IdTokenSessionClaims} still writes {@code auth_time} into the new ID token as epoch seconds.
     */
    static OAuth2Authorization withDateAuthTime(final OAuth2Authorization authorization) {
        if (authorization == null) {
            return null;
        }
        final OAuth2Authorization.Token<OidcIdToken> idToken = authorization.getToken(OidcIdToken.class);
        if (idToken == null || idToken.getToken().getClaims() == null
                || !(idToken.getToken().getClaims().get(IdTokenSessionClaims.AUTH_TIME) instanceof Number seconds)) {
            return authorization;
        }
        final OidcIdToken token = idToken.getToken();
        final Map<String, Object> claims = new LinkedHashMap<>(token.getClaims());
        claims.put(IdTokenSessionClaims.AUTH_TIME, Date.from(Instant.ofEpochSecond(seconds.longValue())));
        final OidcIdToken withDate = new OidcIdToken(token.getTokenValue(), token.getIssuedAt(), token.getExpiresAt(),
                claims);
        final Map<String, Object> metadata = idToken.getMetadata();
        return OAuth2Authorization.from(authorization).token(withDate, m -> {
            m.clear();
            m.putAll(metadata);
        }).build();
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
        final jakarta.servlet.http.HttpSession existingSession = request.getSession(false);
        final String acr = existingSession != null
                && existingSession.getAttribute(AuthTimeStamper.ACR_SESSION_ATTRIBUTE) instanceof String value
                && !value.isBlank() ? value : null;
        if (sid == null && authTime == null && acr == null) {
            return authorization;
        }
        final OAuth2Authorization.Builder builder = OAuth2Authorization.from(authorization);
        if (sid != null) {
            builder.attribute(SID_ATTRIBUTE, sid);
            // So logout can end exactly this browser login (and not the user's other sessions).
            if (existingSession != null) {
                builder.attribute(HTTP_SESSION_ATTRIBUTE, existingSession.getId());
            }
        }
        if (authTime != null) {
            builder.attribute(AUTH_TIME_ATTRIBUTE, authTime);
        }
        if (acr != null) {
            // Task 3: the brokered level of assurance (eID SAML / EUDI Wallet) — never set by a password login.
            builder.attribute(ACR_ATTRIBUTE, acr);
        }
        return builder.build();
    }

    private static HttpServletRequest currentRequest() {
        final RequestAttributes attributes = RequestContextHolder.getRequestAttributes();
        return attributes instanceof ServletRequestAttributes servlet ? servlet.getRequest() : null;
    }
}
