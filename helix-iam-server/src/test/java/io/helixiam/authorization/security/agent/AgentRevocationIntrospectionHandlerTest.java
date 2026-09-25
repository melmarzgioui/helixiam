/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.security.agent;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import io.helixiam.authorization.amqp.agent.AgentClientQuery;
import io.helixiam.authorization.amqp.agent.AgentIdentityDto;
import io.helixiam.authorization.amqp.agent.AgentIdentityPublisher;
import io.helixiam.authorization.security.realm.RealmContextHolder;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenIntrospection;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2TokenIntrospectionAuthenticationToken;

/**
 * Gap 7: the introspection response for an agent (nhi) token is forced to {@code active:false} once the
 * agent is no longer ACTIVE, so a resource server that introspects sees the kill-switch ahead of expiry.
 */
class AgentRevocationIntrospectionHandlerTest {

    private static final String REALM = "master";
    private static final String AGENT_CLIENT = "agent-1";

    private AgentIdentityPublisher agents;
    private AgentRevocationIntrospectionHandler handler;

    @BeforeEach
    void setUp() {
        agents = mock(AgentIdentityPublisher.class);
        handler = new AgentRevocationIntrospectionHandler(agents);
        RealmContextHolder.set(REALM);
    }

    @AfterEach
    void tearDown() {
        RealmContextHolder.clear();
    }

    private AgentIdentityDto agent(final String status, final Long expiresAt) {
        return new AgentIdentityDto("agent-uuid", REALM, "Agent One", null, null, "owner", status,
                "client_secret", AGENT_CLIENT, "read", true, null, expiresAt, null, "read");
    }

    private OAuth2TokenIntrospection agentToken() {
        return OAuth2TokenIntrospection.builder(true)
                .claim("nhi", Boolean.TRUE).claim("client_id", AGENT_CLIENT).claim("sub", "alice").build();
    }

    @Test
    void leavesAnActiveAgentTokenUntouched() {
        when(agents.findByClient(any(AgentClientQuery.class))).thenReturn(agent("ACTIVE", null));

        final OAuth2TokenIntrospection out = handler.revokeIfAgentInactive(agentToken());

        assertThat(out.getClaims()).containsEntry("active", Boolean.TRUE);
        assertThat(out.getClaims()).containsEntry("client_id", AGENT_CLIENT);
    }

    @Test
    void forcesInactiveWhenTheAgentIsSuspended() {
        when(agents.findByClient(any(AgentClientQuery.class))).thenReturn(agent("SUSPENDED", null));

        final OAuth2TokenIntrospection out = handler.revokeIfAgentInactive(agentToken());

        assertThat(out.getClaims()).containsEntry("active", Boolean.FALSE);
        assertThat(out.getClaims()).doesNotContainKey("client_id");
    }

    @Test
    void forcesInactiveWhenTheAgentExpired() {
        when(agents.findByClient(any(AgentClientQuery.class)))
                .thenReturn(agent("ACTIVE", System.currentTimeMillis() - 1_000L));

        assertThat(handler.revokeIfAgentInactive(agentToken()).getClaims()).containsEntry("active", Boolean.FALSE);
    }

    @Test
    void forcesInactiveWhenTheAgentWasRemoved() {
        when(agents.findByClient(any(AgentClientQuery.class))).thenReturn(null);

        assertThat(handler.revokeIfAgentInactive(agentToken()).getClaims()).containsEntry("active", Boolean.FALSE);
    }

    @Test
    void leavesANonAgentTokenUntouched_withoutAnyRegistryLookup() {
        final OAuth2TokenIntrospection userToken = OAuth2TokenIntrospection.builder(true)
                .claim("client_id", "web-app").claim("sub", "alice").build();

        final OAuth2TokenIntrospection out = handler.revokeIfAgentInactive(userToken);

        assertThat(out.getClaims()).containsEntry("active", Boolean.TRUE);
        // agents publisher is never consulted for a non-agent token (default mock returns null -> would flip it).
        assertThat(out.getClaims()).containsEntry("client_id", "web-app");
    }

    @Test
    void failsOpenOnATransientLookupError() {
        when(agents.findByClient(any(AgentClientQuery.class))).thenThrow(new RuntimeException("amqp down"));

        assertThat(handler.revokeIfAgentInactive(agentToken()).getClaims()).containsEntry("active", Boolean.TRUE);
    }

    @Test
    void writesAnInactiveJsonBodyForARevokedAgentOverTheWire() throws Exception {
        when(agents.findByClient(any(AgentClientQuery.class))).thenReturn(agent("REVOKED", null));
        final MockHttpServletResponse response = new MockHttpServletResponse();

        handler.onAuthenticationSuccess(new MockHttpServletRequest(), response,
                new OAuth2TokenIntrospectionAuthenticationToken("tok",
                        new org.springframework.security.authentication.TestingAuthenticationToken("rs", "n/a"),
                        agentToken()));

        assertThat(response.getContentAsString()).contains("\"active\":false");
        assertThat(response.getContentAsString()).doesNotContain(AGENT_CLIENT);
    }
}
