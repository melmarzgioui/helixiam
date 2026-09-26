/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.e2e;

import com.fasterxml.jackson.databind.JsonNode;
import com.nimbusds.jwt.JWTClaimsSet;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * 1.0 item 5: RFC 8693 token exchange honours {@code audience} / {@code resource}, refuses unknown targets and
 * targets whose policy does not allow the requesting client ({@code invalid_target}), and records the acting
 * client in {@code act}. Before the fix the exchanged token always had {@code aud=[<requesting client>]}.
 */
class TokenExchangeE2eTest extends AbstractE2eTest {

    private static final String TOKEN_EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange";
    private static final String ACCESS_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token";
    private static final String PASSWORD = "T0ken-Exchange-Passw0rd!";

    private String realm;
    private E2eSeed.SeededClient web;
    private E2eSeed.SeededClient portal;
    private E2eSeed.SeededClient ledger;
    private E2eSeed.SeededUser joe;
    private String orgId;
    private String joeToken;

    @BeforeEach
    void setUp() {
        realm = E2eSeed.unique("monthfold");
        seed().realm(realm);
        final List<String> grants = List.of("authorization_code", "refresh_token", TOKEN_EXCHANGE);
        web = seed().client(realm, "web", grants, List.of(E2eSeed.REDIRECT_URI), List.of("openid", "profile"), false);
        portal = seed().client(realm, "portal", grants, List.of(E2eSeed.REDIRECT_URI), List.of("openid", "profile"), false);
        ledger = seed().serviceAccountClient(realm, "ledger", List.of("openid"));
        joe = seed().user(realm, E2eSeed.unique("joe"), PASSWORD);

        final E2eAdminSession admin = adminSession(realm);
        final E2eHttp.Response org = admin.post("/admin/realms/" + realm + "/organizations", Map.of("name", "harbor-pine"));
        assertThat(org.status()).as(org.toString()).isEqualTo(201);
        orgId = org.json().path("orgId").asText();
        final E2eHttp.Response member = admin.put("/admin/realms/" + realm + "/organizations/" + orgId + "/members/"
                + joe.userId(), Map.of("role", "owner"));
        assertThat(member.status()).as(member.toString()).isBetween(200, 204);
        // ledger's policy: only `web` may exchange tokens for it.
        final E2eHttp.Response policy = admin.put("/admin/realms/" + realm + "/clients/ledger/token-exchange",
                Map.of("allowedClients", List.of("web")));
        assertThat(policy.status()).as(policy.toString()).isEqualTo(200);

        joeToken = oidc(realm).authorizationCode("web", web.secret(), web.redirectUri(), joe.username(), PASSWORD, "openid profile")
                .accessToken();
    }

    @Test
    void audienceLedger_givesAudLedger_actWeb_andKeepsTheSubjectsOrganizations() {
        final E2eHttp.Response r = exchange(web, Map.of("audience", "ledger"));
        assertThat(r.status()).as(r.toString()).isEqualTo(200);

        final OidcFlow oidc = oidc(realm);
        final JWTClaimsSet exchanged = oidc.verify(r.json().path("access_token").asText());
        assertThat(exchanged.getAudience()).containsExactly("ledger");
        assertThat(exchanged.getSubject()).isEqualTo(joe.userId());
        assertThat(exchanged.getIssuer()).isEqualTo(oidc.issuer());
        assertThat(exchanged.getClaim("act")).isInstanceOf(Map.class);
        assertThat(((Map<?, ?>) exchanged.getClaim("act")).get("sub")).isEqualTo("web");

        final JsonNode orgs = r.json().path("access_token").isMissingNode() ? null
                : new com.fasterxml.jackson.databind.ObjectMapper().valueToTree(OidcFlow.claims(r.json().path("access_token").asText()))
                .path("organizations");
        assertThat(orgs).isNotNull();
        assertThat(orgs.isArray()).as("organizations claim kept: %s", orgs).isTrue();
        assertThat(orgs.get(0).path("id").asText()).isEqualTo(orgId);
        assertThat(orgs.get(0).path("roles").toString()).contains("owner");
    }

    @Test
    void unknownAudience_isInvalidTarget() {
        final E2eHttp.Response r = exchange(web, Map.of("audience", "no-such-client"));
        assertThat(r.status()).as(r.toString()).isEqualTo(400);
        assertThat(r.json().path("error").asText()).isEqualTo("invalid_target");
    }

    @Test
    void exchangeTheTargetsPolicyDoesNotAllow_isRefused() {
        final String portalToken = oidc(realm).authorizationCode("portal", portal.secret(), portal.redirectUri(), joe.username(),
                PASSWORD, "openid profile").accessToken();
        final E2eHttp.Response r = oidc(realm).tokenEndpoint("portal", portal.secret(), Map.of(
                "grant_type", TOKEN_EXCHANGE, "subject_token", portalToken, "subject_token_type", ACCESS_TOKEN_TYPE,
                "audience", "ledger"));
        assertThat(r.status()).as(r.toString()).isEqualTo(400);
        assertThat(r.json().path("error").asText()).isEqualTo("invalid_target");
    }

    @Test
    void resourceIndicator_setsAud_andAnUnregisteredResourceIsInvalidTarget() {
        final E2eAdminSession admin = adminSession(realm);
        final E2eHttp.Response allow = admin.put("/admin/realms/" + realm + "/clients/web/allowed-resources",
                Map.of("resources", List.of("https://ledger.monthfold.test/api")));
        assertThat(allow.status()).as(allow.toString()).isBetween(200, 204);

        final E2eHttp.Response ok = exchange(web, Map.of("resource", "https://ledger.monthfold.test/api"));
        assertThat(ok.status()).as(ok.toString()).isEqualTo(200);
        assertThat(oidc(realm).verify(ok.json().path("access_token").asText()).getAudience())
                .containsExactly("https://ledger.monthfold.test/api");

        final E2eHttp.Response unknown = exchange(web, Map.of("resource", "https://evil.example/api"));
        assertThat(unknown.status()).as(unknown.toString()).isEqualTo(400);
        assertThat(unknown.json().path("error").asText()).isEqualTo("invalid_target");
    }

    private E2eHttp.Response exchange(final E2eSeed.SeededClient client, final Map<String, String> target) {
        final Map<String, String> form = new java.util.HashMap<>(Map.of("grant_type", TOKEN_EXCHANGE,
                "subject_token", joeToken, "subject_token_type", ACCESS_TOKEN_TYPE));
        form.putAll(target);
        return oidc(realm).tokenEndpoint(client.clientId(), client.secret(), form);
    }
}
