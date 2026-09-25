/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.idp.agent;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.List;
import java.util.Map;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import io.helixiam.authorization.amqp.agent.AgentClientQuery;
import io.helixiam.authorization.amqp.agent.AgentIdentityDto;
import io.helixiam.authorization.amqp.agent.AgentIdentityPublisher;
import io.helixiam.authorization.amqp.realm.RealmAdminPublisher;
import io.helixiam.authorization.security.realm.RealmContextHolder;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.ResponseEntity;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;

/**
 * Security tests for the on-behalf-of exchange. Gap-1: the subject_token must be bound to the acting
 * agent (aud/azp/may_act) — otherwise any user access token the realm minted could be replayed by any
 * registered agent.
 */
class DelegationTokenControllerTest {

    private static final String TOKEN_EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange";
    private static final String REALM = "master";
    private static final String ISSUER = "https://idp.test/realms/master";
    private static final String AGENT = "agent-1";
    private static final String USER = "alice";

    private RSAKey signingKey;
    private DelegationTokenController strict;
    private DelegationTokenController loose;

    @BeforeEach
    void setUp() throws Exception {
        signingKey = new RSAKeyGenerator(2048).keyID("realm-master-1").generate();
        final JWKSource<SecurityContext> publicJwks = new ImmutableJWKSet<>(new JWKSet(signingKey.toPublicJWK()));
        final JwtEncoder encoder = new NimbusJwtEncoder(new ImmutableJWKSet<>(new JWKSet(signingKey)));

        // realmAdmin.get() returns null -> realmIssuer falls back to settings issuer + /realms/<realm>.
        final RealmAdminPublisher realmAdmin = mock(RealmAdminPublisher.class);
        final AgentIdentityPublisher agents = mock(AgentIdentityPublisher.class);
        final AgentIdentityDto active = new AgentIdentityDto("agent-uuid", REALM, "Agent One", null, null,
                "owner", "ACTIVE", "client_secret", AGENT, "read", true, null, null, null, "read");
        when(agents.findByClient(any(AgentClientQuery.class))).thenReturn(active);

        final AuthorizationServerSettings settings =
                AuthorizationServerSettings.builder().issuer("https://idp.test").build();

        strict = new DelegationTokenController(encoder, publicJwks, realmAdmin, agents, settings, 300, true, 3);
        loose = new DelegationTokenController(encoder, publicJwks, realmAdmin, agents, settings, 300, false, 3);
        RealmContextHolder.set(REALM);
    }

    @AfterEach
    void tearDown() {
        RealmContextHolder.clear();
    }

    @Test
    void mintsWhenSubjectTokenNamesTheAgentInAud() throws Exception {
        final ResponseEntity<Map<String, Object>> resp =
                strict.exchange(TOKEN_EXCHANGE, subjectToken(List.of(AGENT), null), actorToken(), "read", null,
                        new MockHttpServletRequest());
        assertThat(resp.getStatusCode().value()).isEqualTo(200);
        assertThat(resp.getBody()).containsKey("access_token");
    }

    @Test
    void rejectsWhenSubjectTokenIsNotBoundToTheAgent() throws Exception {
        final ResponseEntity<Map<String, Object>> resp =
                strict.exchange(TOKEN_EXCHANGE, subjectToken(List.of("some-other-client"), null), actorToken(),
                        "read", null, new MockHttpServletRequest());
        assertThat(resp.getStatusCode().value()).isEqualTo(403);
        assertThat(resp.getBody()).containsEntry("error", "invalid_grant");
    }

    @Test
    void mintsWhenSubjectTokenCarriesAMayActNamingTheAgent() throws Exception {
        final ResponseEntity<Map<String, Object>> resp =
                strict.exchange(TOKEN_EXCHANGE, subjectToken(null, Map.of("sub", AGENT)), actorToken(), "read",
                        null, new MockHttpServletRequest());
        assertThat(resp.getStatusCode().value()).isEqualTo(200);
    }

    @Test
    void looseModeAcceptsAnUnboundSubjectToken() throws Exception {
        final ResponseEntity<Map<String, Object>> resp =
                loose.exchange(TOKEN_EXCHANGE, subjectToken(List.of("some-other-client"), null), actorToken(),
                        "read", null, new MockHttpServletRequest());
        assertThat(resp.getStatusCode().value()).isEqualTo(200);
    }

    @Test
    void rejectsWhenTheDelegationChainIsTooDeep() throws Exception {
        // Actor already acting at depth 3 (== max); one more exchange would be depth 4 -> refuse.
        final Map<String, Object> act3 = Map.of("sub", "a1", "act", Map.of("sub", "a2", "act", Map.of("sub", "a3")));
        final String actor = sign(new JWTClaimsSet.Builder()
                .subject(AGENT).issuer(ISSUER).claim("nhi", Boolean.TRUE).claim("azp", AGENT)
                .claim("realm_access", Map.of("roles", List.of("read"))).claim("act", act3).build());

        final ResponseEntity<Map<String, Object>> resp =
                strict.exchange(TOKEN_EXCHANGE, subjectToken(List.of(AGENT), null), actor, "read", null,
                        new MockHttpServletRequest());
        assertThat(resp.getStatusCode().value()).isEqualTo(400);
        assertThat(resp.getBody().get("error_description").toString()).contains("chain too deep");
    }

    private String actorToken() throws Exception {
        return sign(new JWTClaimsSet.Builder()
                .subject(AGENT).issuer(ISSUER)
                .claim("nhi", Boolean.TRUE).claim("azp", AGENT)
                .claim("realm_access", Map.of("roles", List.of("read"))).build());
    }

    private String subjectToken(final List<String> aud, final Map<String, Object> mayAct) throws Exception {
        final JWTClaimsSet.Builder b = new JWTClaimsSet.Builder()
                .subject(USER).issuer(ISSUER)
                .claim("realm_access", Map.of("roles", List.of("read")));
        if (aud != null) {
            b.audience(aud);
        }
        if (mayAct != null) {
            b.claim("may_act", mayAct);
        }
        return sign(b.build());
    }

    private String sign(final JWTClaimsSet claims) throws Exception {
        final SignedJWT jwt = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(signingKey.getKeyID()).build(), claims);
        jwt.sign(new RSASSASigner(signingKey));
        return jwt.serialize();
    }
}
