/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.e2e;

import com.fasterxml.jackson.databind.JsonNode;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * RFC 8693 on-behalf-of delegation ({@code /agent/delegation/token}) in a non-master realm, with the agent's roles
 * configured the normal way (the console's role picker and the admin API take plain realm role names). The delegated
 * token must carry the role that both the user and the agent have, in the documented token form
 * ({@code <role>_<realm>} for a user's realm role, docs/role-names-in-tokens.md), and nothing the agent lacks.
 */
class AgentDelegationRolesE2eTest extends AbstractE2eTest {

    private static final String PASSWORD = "Delegation-Passw0rd!";
    private static final String EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange";

    @Test
    void theDelegatedTokenCarriesTheRoleBothTheUserAndTheAgentHave() {
        final String realm = E2eSeed.unique("deleg");
        seed().realm(realm);
        final E2eAdminSession admin = adminSession(realm);
        final String accountant = createRole(admin, realm, "accountant");
        final String auditor = createRole(admin, realm, "reviewer");

        final E2eSeed.SeededUser joe = seed().user(realm, E2eSeed.unique("joe"), PASSWORD);
        for (final String roleId : List.of(accountant, auditor)) {
            assertThat(admin.post("/admin/realms/" + realm + "/users/" + joe.userId() + "/roles",
                    Map.of("roleId", roleId)).status()).isEqualTo(204);
        }

        // The agent's own client: the user signs in to it (so the user token names the agent), and the agent
        // authenticates with client_credentials.
        final E2eSeed.SeededClient agentClient = seed().client(realm, E2eSeed.unique("bookkeeper"),
                List.of("authorization_code", "refresh_token", "client_credentials"), List.of(E2eSeed.REDIRECT_URI),
                List.of("openid"), false);
        final E2eHttp.Response agent = admin.post("/admin/realms/" + realm + "/agents", Map.of(
                "name", E2eSeed.unique("bookkeeper-agent"), "owner", joe.userId(), "clientId", agentClient.clientId(),
                "roles", "accountant"));
        assertThat(agent.status()).as(agent.toString()).isEqualTo(201);

        final OidcFlow.Tokens user = oidc(realm).authorizationCode(agentClient.clientId(), agentClient.secret(),
                agentClient.redirectUri(), joe.username(), PASSWORD, "openid");
        assertThat(realmRoles(user.accessToken())).contains("accountant_" + realm, "reviewer_" + realm);
        final String agentToken = oidc(realm).clientCredentials(agentClient.clientId(), agentClient.secret(), "openid")
                .accessToken();
        assertThat(OidcFlow.claims(agentToken).get("nhi")).isEqualTo(true);
        assertThat(realmRoles(agentToken)).contains("accountant");

        final E2eHttp.Response exchanged = newBrowser().postForm("/realms/" + realm + "/agent/delegation/token",
                Map.of("grant_type", EXCHANGE, "subject_token", user.accessToken(), "actor_token", agentToken),
                "Authorization", OidcFlow.basic(agentClient.clientId(), agentClient.secret()),
                "Accept", "application/json");
        assertThat(exchanged.status()).as(exchanged.toString()).isEqualTo(200);
        final String delegated = exchanged.json().path("access_token").asText();
        final Map<String, Object> claims = OidcFlow.claims(delegated);
        assertThat(claims.get("sub")).isEqualTo(joe.userId());
        assertThat(realmRoles(delegated)).as("user ∩ agent, in the token's documented form")
                .containsExactly("accountant_" + realm);

        // A requested narrowing works with either spelling of the role.
        for (final String scope : List.of("accountant", "accountant_" + realm)) {
            final E2eHttp.Response narrowed = newBrowser().postForm("/realms/" + realm + "/agent/delegation/token",
                    Map.of("grant_type", EXCHANGE, "subject_token", user.accessToken(), "actor_token", agentToken,
                            "scope", scope),
                    "Authorization", OidcFlow.basic(agentClient.clientId(), agentClient.secret()),
                    "Accept", "application/json");
            assertThat(narrowed.status()).as(narrowed.toString()).isEqualTo(200);
            assertThat(realmRoles(narrowed.json().path("access_token").asText())).as(scope)
                    .containsExactly("accountant_" + realm);
        }
    }

    private static String createRole(final E2eAdminSession admin, final String realm, final String name) {
        assertThat(admin.post("/admin/realms/" + realm + "/roles", Map.of("name", name)).status()).isEqualTo(201);
        for (final JsonNode r : admin.get("/admin/realms/" + realm + "/roles").json()) {
            if (name.equals(r.path("name").asText())) {
                return r.path("roleId").asText();
            }
        }
        throw new AssertionError("no role " + name);
    }

    @SuppressWarnings("unchecked")
    private static List<String> realmRoles(final String jwt) {
        final Object realmAccess = OidcFlow.claims(jwt).get("realm_access");
        assertThat(realmAccess).as("realm_access").isInstanceOf(Map.class);
        return (List<String>) ((Map<String, Object>) realmAccess).get("roles");
    }
}
