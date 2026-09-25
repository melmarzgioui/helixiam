/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.security.agent;

import io.helixiam.authorization.amqp.agent.AgentClientQuery;
import io.helixiam.authorization.amqp.agent.AgentIdentityDto;
import io.helixiam.authorization.amqp.agent.AgentIdentityPublisher;
import io.helixiam.authorization.security.realm.RealmContextHolder;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.http.MediaType;
import org.springframework.http.server.ServletServerHttpResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenIntrospection;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2TokenIntrospectionAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.http.converter.OAuth2TokenIntrospectionHttpMessageConverter;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import java.io.IOException;
import java.util.Map;

/**
 * Helix IAM Agent (NHI) kill-switch, introspection side (Phase 1: gap 7). The agent lifecycle gate runs at
 * token <em>issuance</em>, so revoking/suspending an agent stops new mints immediately — but a delegated or
 * agent access token minted just before that stays cryptographically valid until it expires (Helix mints
 * these short-lived by design). This handler re-checks the live agent status on the RFC 7662 introspection
 * response: for a token that carries {@code nhi}/{@code agent_id}, if the agent is no longer ACTIVE (or gone),
 * the response is forced to {@code active:false} so any resource server that introspects sees the revocation
 * at once, ahead of natural expiry. Non-agent tokens pass through unchanged. It only shapes the introspection
 * response — the token-validation hot path is untouched — so RSes that validate the JWT locally still rely on
 * the short token lifetime for revocation latency.
 */
public class AgentRevocationIntrospectionHandler implements AuthenticationSuccessHandler {

    private static final Logger LOG = LogManager.getLogger(AgentRevocationIntrospectionHandler.class);

    private final AgentIdentityPublisher agents;
    private final OAuth2TokenIntrospectionHttpMessageConverter converter =
            new OAuth2TokenIntrospectionHttpMessageConverter();

    public AgentRevocationIntrospectionHandler(final AgentIdentityPublisher agents) {
        this.agents = agents;
    }

    @Override
    public void onAuthenticationSuccess(final HttpServletRequest request, final HttpServletResponse response,
                                        final Authentication authentication) throws IOException {
        final OAuth2TokenIntrospection claims =
                ((OAuth2TokenIntrospectionAuthenticationToken) authentication).getTokenClaims();
        this.converter.write(revokeIfAgentInactive(claims), MediaType.APPLICATION_JSON,
                new ServletServerHttpResponse(response));
    }

    /**
     * Returns {@code active:false} when the introspected token belongs to an agent that is no longer ACTIVE
     * (revoked/suspended/expired) or has been removed; otherwise returns the claims unchanged. A transient
     * lookup error fails open (the token's own claims stand) — the short token lifetime still bounds exposure.
     */
    OAuth2TokenIntrospection revokeIfAgentInactive(final OAuth2TokenIntrospection claims) {
        final Map<String, Object> c = claims.getClaims();
        if (!Boolean.TRUE.equals(c.get("active")) || !isAgentToken(c)) {
            return claims;
        }
        final String clientId = firstNonBlank(str(c.get("client_id")), str(c.get("azp")));
        if (clientId == null) {
            return claims;
        }
        try {
            final AgentIdentityDto agent = agents.findByClient(new AgentClientQuery(RealmContextHolder.get(), clientId));
            if (agent == null) {
                return inactive(); // the agent was removed -> its live tokens are revoked
            }
            if (AgentTokenEnricher.denialReason(agent.status(), agent.expiresAt(), System.currentTimeMillis()) != null) {
                return inactive(); // suspended / revoked / expired agent
            }
        } catch (final RuntimeException e) {
            LOG.debug("introspection agent re-check failed for {}: {}", clientId, e.getMessage());
        }
        return claims;
    }

    private static OAuth2TokenIntrospection inactive() {
        return OAuth2TokenIntrospection.builder(false).build();
    }

    private static boolean isAgentToken(final Map<String, Object> c) {
        return Boolean.TRUE.equals(c.get("nhi")) || c.get("agent_id") != null;
    }

    private static String firstNonBlank(final String a, final String b) {
        if (a != null && !a.isBlank()) {
            return a;
        }
        return (b != null && !b.isBlank()) ? b : null;
    }

    private static String str(final Object o) {
        return o == null ? null : o.toString();
    }
}
