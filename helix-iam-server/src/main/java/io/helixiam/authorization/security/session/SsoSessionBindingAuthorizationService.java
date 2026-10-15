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
    /** Verify-only wallet step: the {@code verified_claims} JSON released for this authorization (id_token only). */
    public static final String VERIFIED_CLAIMS_ATTRIBUTE = "helix_verified_claims";

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
        // Security review item 1: an authorization removed in the browser (consent denied) ends any pending release.
        final HttpServletRequest request = currentRequest();
        final jakarta.servlet.http.HttpSession session = request == null ? null : request.getSession(false);
        if (session != null) {
            session.removeAttribute(AuthTimeStamper.VERIFIED_CLAIMS_SESSION_ATTRIBUTE);
        }
        delegate.remove(authorization);
    }

    /** The scope a client must request for the verify-only wallet step's {@code verified_claims} (review item 7). */
    public static final String VERIFIED_CLAIMS_SCOPE = "verified_claims";

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
     * {@code ClassCastException} (HTTP 500). The loaded authorization is handed out with its ID token's
     * {@code auth_time} claim as a {@link Date} of the same instant; the token value and the token's claims metadata
     * keep epoch seconds, and {@link IdTokenSessionClaims} still writes {@code auth_time} into every new ID token as
     * epoch seconds. Loading itself writes nothing, but whatever Spring Authorization Server saves back is this
     * authorization: a refresh replaces the ID token, while a revocation or invalidation stores it again, now with the
     * {@code Date} form, which later loads hand out unchanged ({@code RefreshAuthTimeTest}).
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
        if (authorization != null && authorization.getAccessToken() != null) {
            final OAuth2Authorization stripped = withoutVerifiedClaims(authorization);
            if (stripped != authorization) {
                return stripped;
            }
        }
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
        final String verifiedClaims = verifiedClaimsFor(authorization, existingSession);
        if (sid == null && authTime == null && acr == null && verifiedClaims == null) {
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
        if (verifiedClaims != null) {
            // Verify-only wallet step (design D6): the released claims go to THIS code only — the authorization
            // request the step-up completed — never to a later code of another client in the same SSO session.
            builder.attribute(VERIFIED_CLAIMS_ATTRIBUTE, verifiedClaims);
        }
        return builder.build();
    }

    /**
     * Security review items 1 and 7: the pending {@code verified_claims} of the session, consumed by this code: bound
     * only when it was released for exactly this authorization request (client and request hash), has not expired and
     * the client was granted the {@value #VERIFIED_CLAIMS_SCOPE} scope; dropped in every case.
     */
    private static String verifiedClaimsFor(final OAuth2Authorization authorization,
                                            final jakarta.servlet.http.HttpSession session) {
        if (session == null
                || !(session.getAttribute(AuthTimeStamper.VERIFIED_CLAIMS_SESSION_ATTRIBUTE) instanceof String pending)) {
            return null;
        }
        session.removeAttribute(AuthTimeStamper.VERIFIED_CLAIMS_SESSION_ATTRIBUTE);
        final Object raw = authorization.getAttribute(
                org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest.class.getName());
        if (!(raw instanceof org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest request)
                || authorization.getAuthorizedScopes() == null
                || !authorization.getAuthorizedScopes().contains(VERIFIED_CLAIMS_SCOPE)) {
            return null;
        }
        final Object nonce = request.getAdditionalParameters().get("nonce");
        final String hash = PendingVerifiedClaims.requestHash(request.getClientId(), request.getState(),
                nonce instanceof String n ? n : null, request.getRedirectUri());
        return PendingVerifiedClaims.claimsFor(pending, request.getClientId(), hash, java.time.Instant.now())
                .orElse(null);
    }

    /**
     * Security review items 2 (and its re-review): once the code is exchanged, the stored authorization keeps no
     * {@code verified_claims}: neither the attribute nor the ID token's parsed claims or claims metadata (every store
     * persists those). The token VALUE (the signed JWT the client already holds) is kept as is: re-signing it is not
     * possible and the value is how {@code id_token_hint} finds the authorization, so it still encodes the released
     * claims until the authorization is removed (documented in docs/eudi-wallet.md §12).
     */
    static OAuth2Authorization withoutVerifiedClaims(final OAuth2Authorization authorization) {
        final OAuth2Authorization.Token<org.springframework.security.oauth2.core.oidc.OidcIdToken> idToken =
                authorization.getToken(org.springframework.security.oauth2.core.oidc.OidcIdToken.class);
        final boolean inToken = idToken != null && idToken.getToken().getClaims() != null
                && idToken.getToken().getClaims().containsKey(IdTokenSessionClaims.VERIFIED_CLAIMS);
        final boolean inMetadata = idToken != null && idToken.getClaims() != null
                && idToken.getClaims().containsKey(IdTokenSessionClaims.VERIFIED_CLAIMS);
        if (authorization.getAttribute(VERIFIED_CLAIMS_ATTRIBUTE) == null && !inToken && !inMetadata) {
            return authorization;
        }
        final OAuth2Authorization.Builder builder = OAuth2Authorization.from(authorization)
                .attributes(attributes -> attributes.remove(VERIFIED_CLAIMS_ATTRIBUTE));
        if (inToken || inMetadata) {
            final org.springframework.security.oauth2.core.oidc.OidcIdToken token = idToken.getToken();
            final Map<String, Object> claims = new LinkedHashMap<>(token.getClaims());
            claims.remove(IdTokenSessionClaims.VERIFIED_CLAIMS);
            final org.springframework.security.oauth2.core.oidc.OidcIdToken without =
                    new org.springframework.security.oauth2.core.oidc.OidcIdToken(token.getTokenValue(),
                            token.getIssuedAt(), token.getExpiresAt(), claims);
            final Map<String, Object> metadata = new LinkedHashMap<>(idToken.getMetadata());
            if (metadata.get(OAuth2Authorization.Token.CLAIMS_METADATA_NAME) instanceof Map<?, ?> stored) {
                final Map<String, Object> copy = new LinkedHashMap<>();
                stored.forEach((k, v) -> copy.put(String.valueOf(k), v));
                copy.remove(IdTokenSessionClaims.VERIFIED_CLAIMS);
                metadata.put(OAuth2Authorization.Token.CLAIMS_METADATA_NAME, copy);
            }
            builder.token(without, m -> {
                m.clear();
                m.putAll(metadata);
            });
        }
        return builder.build();
    }

    private static HttpServletRequest currentRequest() {
        final RequestAttributes attributes = RequestContextHolder.getRequestAttributes();
        return attributes instanceof ServletRequestAttributes servlet ? servlet.getRequest() : null;
    }
}
