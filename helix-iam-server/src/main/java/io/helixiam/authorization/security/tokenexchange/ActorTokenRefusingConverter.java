/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.security.tokenexchange;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.web.authentication.AuthenticationConverter;

/**
 * RFC 8693 delegation on {@code /oauth2/token} is not supported: a token exchange carrying {@code actor_token} or
 * {@code actor_token_type} is refused with {@code invalid_request}. HelixIAM's supported delegation is
 * {@code /agent/delegation/token}.
 *
 * <p>Why: Spring Security 7 can now store an exchange with an actor (Spring Authorization Server 1.5 could not
 * serialize the actor, so 1.0 never completed one), and HelixIAM's {@code act} claim names the requesting client, not
 * the actor ({@code TokenExchangeTargets}), with no {@code may_act} policy behind it. Until RFC 8693 actor semantics
 * are implemented properly, the request is refused before any provider runs, so nothing is issued or stored.
 *
 * <p>Registered first among the token endpoint's request converters; for any other request it returns {@code null} so
 * the next converter handles it.
 */
public final class ActorTokenRefusingConverter implements AuthenticationConverter {

    static final String ACTOR_TOKEN = "actor_token";
    static final String ACTOR_TOKEN_TYPE = "actor_token_type";

    @Override
    public Authentication convert(final HttpServletRequest request) {
        if (!AuthorizationGrantType.TOKEN_EXCHANGE.getValue().equals(request.getParameter(OAuth2ParameterNames.GRANT_TYPE))) {
            return null;
        }
        if (request.getParameter(ACTOR_TOKEN) != null || request.getParameter(ACTOR_TOKEN_TYPE) != null) {
            throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST,
                    "actor_token is not supported; delegation is served by /agent/delegation/token", null));
        }
        return null;
    }
}
