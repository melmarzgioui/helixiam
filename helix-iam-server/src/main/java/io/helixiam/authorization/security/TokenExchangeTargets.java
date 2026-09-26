/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.security;

import io.helixiam.authorization.amqp.resource.ResourceIndicatorPublisher;
import io.helixiam.authorization.security.realm.RealmContextHolder;
import io.helixiam.authorization.security.resource.ResourceIndicators;
import io.helixiam.authorization.service.client.TokenExchangePolicyService;
import io.helixiam.authorization.support.RealmScopedKey;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2TokenExchangeAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * 1.0 item 5: RFC 8693 token exchange targets and the {@code act} claim.
 *
 * <ul>
 *   <li>{@code audience} values are client ids of this realm. Each must exist ({@code invalid_target}
 *       otherwise) and its token-exchange policy must list the requesting client ({@code invalid_target},
 *       "not permitted").</li>
 *   <li>{@code resource} values must be on the requesting client's RFC 8707 allow-list ({@code invalid_target}
 *       otherwise).</li>
 *   <li>{@code aud} becomes exactly the requested targets; with no target requested it stays the requesting
 *       client (unchanged behaviour).</li>
 *   <li>{@code act.sub} is the requesting client; an {@code act} already on the subject token is nested as
 *       {@code act.act} (RFC 8693 §4.1).</li>
 * </ul>
 * The subject's claims (sub, roles, organizations) are produced by the regular customizer from the subject
 * principal, so they are kept.
 */
final class TokenExchangeTargets {

    static final String INVALID_TARGET = "invalid_target";

    private TokenExchangeTargets() {
    }

    static void apply(final JwtEncodingContext context, final TokenExchangePolicyService policy,
                      final ResourceIndicatorPublisher resources) {
        if (!(context.getAuthorizationGrant() instanceof OAuth2TokenExchangeAuthenticationToken grant)) {
            return;
        }
        final String realm = RealmContextHolder.get();
        final String requester = context.getRegisteredClient().getClientId();
        final Set<String> aud = new LinkedHashSet<>();

        for (final String target : grant.getAudiences()) {
            switch (policy.decide(realm, requester, target)) {
                case UNKNOWN_TARGET -> throw invalidTarget("Unknown audience: " + target);
                case NOT_ALLOWED -> throw invalidTarget("Token exchange to " + target + " is not permitted for " + requester);
                default -> aud.add(target);
            }
        }
        if (!grant.getResources().isEmpty()) {
            final List<String> allowList = resources.allowedResourcesForClient(RealmScopedKey.pack(realm, requester));
            for (final String resource : grant.getResources()) {
                if (!ResourceIndicators.isValidResource(resource)
                        || !ResourceIndicators.isAllowed(resource, allowList == null ? List.of() : allowList)) {
                    throw invalidTarget("Unknown or not permitted resource: " + resource);
                }
                aud.add(resource);
            }
        }
        if (!aud.isEmpty()) {
            // MUTABLE list — SAS's Jackson claim allowlist rejects immutable collections.
            context.getClaims().audience(new ArrayList<>(aud));
        }

        final Map<String, Object> act = new HashMap<>();
        act.put("sub", requester);
        final Object previous = context.getClaims().build().getClaims().get("act");
        if (previous instanceof Map<?, ?> prior && !requester.equals(prior.get("sub"))) {
            act.put("act", new HashMap<>(prior));
        }
        context.getClaims().claim("act", act);
    }

    private static OAuth2AuthenticationException invalidTarget(final String description) {
        return new OAuth2AuthenticationException(new OAuth2Error(INVALID_TARGET, description, null));
    }
}
