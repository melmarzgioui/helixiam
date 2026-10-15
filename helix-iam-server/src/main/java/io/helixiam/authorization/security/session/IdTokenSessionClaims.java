/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.security.session;

import io.helixiam.common.json.JsonMappers;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;

/**
 * A3: stamps {@code sid} and {@code auth_time} into an ID token from the authorization's SSO-session binding
 * ({@link SsoSessionBindingAuthorizationService}). The binding is made once, when the code is issued, and kept
 * on the authorization, so the code exchange and every refresh carry the same {@code sid} and the time of the
 * last interactive authentication (never the time of the token request). {@code auth_time} is emitted as epoch
 * seconds (a JSON number, as OIDC Core requires).
 *
 * <p>Task 3: the same mechanism carries {@code acr} — the brokered level of assurance of a federated login
 * (eID SAML, EUDI Wallet), bound from {@link SsoSessionBindingAuthorizationService#ACR_ATTRIBUTE}. Absent
 * for a password login, which never sets it.
 */
public final class IdTokenSessionClaims {

    public static final String SID = "sid";
    public static final String AUTH_TIME = "auth_time";
    public static final String ACR = "acr";
    /** Verify-only wallet step: the OIDC-for-Identity-Assurance-style object of verified attributes. */
    public static final String VERIFIED_CLAIMS = "verified_claims";
    private static final tools.jackson.databind.ObjectMapper JSON = JsonMappers.plain();

    private IdTokenSessionClaims() {
    }

    /** Adds the session claims to an {@code id_token}; any other token type is left untouched. */
    public static void apply(final JwtEncodingContext context) {
        if (context.getTokenType() == null || !"id_token".equals(context.getTokenType().getValue())) {
            return;
        }
        final OAuth2Authorization authorization = context.getAuthorization();
        if (authorization == null) {
            return;
        }
        final Object sid = authorization.getAttribute(SsoSessionBindingAuthorizationService.SID_ATTRIBUTE);
        final Object authTime = authorization.getAttribute(SsoSessionBindingAuthorizationService.AUTH_TIME_ATTRIBUTE);
        final Object acr = authorization.getAttribute(SsoSessionBindingAuthorizationService.ACR_ATTRIBUTE);
        context.getClaims().claims(claims -> {
            if (sid instanceof String value && !value.isBlank()) {
                claims.put(SID, value);
            }
            if (authTime instanceof Long seconds) {
                claims.put(AUTH_TIME, seconds);
            }
            if (acr instanceof String value && !value.isBlank()) {
                claims.put(ACR, value);
            }
        });
        final Object verified = authorization.getAttribute(SsoSessionBindingAuthorizationService.VERIFIED_CLAIMS_ATTRIBUTE);
        if (verified instanceof String json && !json.isBlank()
                && org.springframework.security.oauth2.core.AuthorizationGrantType.AUTHORIZATION_CODE
                        .equals(context.getAuthorizationGrantType())) {
            // Security review item 2: the code exchange's ID token only, never a refresh's.
            final java.util.Map<String, Object> object = verifiedClaims(json);
            if (object != null) {
                context.getClaims().claims(claims -> claims.put(VERIFIED_CLAIMS, object));
            }
        }
    }

    /**
     * The bound {@code verified_claims} JSON as fresh {@link java.util.LinkedHashMap}s (never immutable collections:
     * SAS's Jackson rejects them when the authorization is stored); {@code null} when it is not a JSON object.
     */
    private static java.util.Map<String, Object> verifiedClaims(final String json) {
        try {
            final Object parsed = JSON.readValue(json, Object.class);
            if (parsed instanceof java.util.Map<?, ?> map) {
                @SuppressWarnings("unchecked")
                final java.util.Map<String, Object> object = (java.util.Map<String, Object>) mutable(map);
                return object;
            }
        } catch (final tools.jackson.core.JacksonException e) {
            return null;
        }
        return null;
    }

    private static Object mutable(final Object value) {
        if (value instanceof java.util.Map<?, ?> map) {
            final java.util.Map<String, Object> out = new java.util.LinkedHashMap<>();
            map.forEach((k, v) -> out.put(String.valueOf(k), mutable(v)));
            return out;
        }
        if (value instanceof java.util.List<?> list) {
            final java.util.List<Object> out = new java.util.ArrayList<>();
            list.forEach(v -> out.add(mutable(v)));
            return out;
        }
        return value;
    }
}
