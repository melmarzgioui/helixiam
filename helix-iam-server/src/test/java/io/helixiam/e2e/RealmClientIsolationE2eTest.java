/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.e2e;

import com.nimbusds.jwt.JWTClaimsSet;
import io.helixiam.authorization.repository.ServiceProviderRepository;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * 1.0 item 2: a client belongs to the realm it was created in, and the same {@code client_id} can exist in two
 * realms. Before the fix every admin-created client got {@code realm_id=master}, so a second realm's clients
 * were unreachable under {@code /realms/{realm}/…} and a second {@code client_id=web} collided.
 */
class RealmClientIsolationE2eTest extends AbstractE2eTest {

    private static final String PASSWORD = "Re4lm-Isolation-Passw0rd!";

    @Test
    void sameClientIdInTwoRealms_eachRunsItsOwnCodeFlow() {
        final String realmA = E2eSeed.unique("firm-a");
        final String realmB = E2eSeed.unique("firm-b");
        seed().realm(realmA);
        seed().realm(realmB);
        final String clientId = E2eSeed.unique("web");
        final E2eSeed.SeededClient webA = seed().confidentialClient(realmA, clientId, List.of("openid", "profile"));
        final E2eSeed.SeededClient webB = seed().confidentialClient(realmB, clientId, List.of("openid", "profile"));

        final ServiceProviderRepository repo = context.getBean(ServiceProviderRepository.class);
        assertThat(repo.findByIdAndDeleted(webA.id(), false)).hasValueSatisfying(c -> assertThat(c.getRealmId()).isEqualTo(realmA));
        assertThat(repo.findByIdAndDeleted(webB.id(), false)).hasValueSatisfying(c -> assertThat(c.getRealmId()).isEqualTo(realmB));

        for (final E2eSeed.SeededClient web : List.of(webA, webB)) {
            final E2eSeed.SeededUser user = seed().user(web.realmId(), E2eSeed.unique("user"), PASSWORD);
            final OidcFlow oidc = oidc(web.realmId());
            final OidcFlow.Tokens tokens = oidc.authorizationCode(web.clientId(), web.secret(), web.redirectUri(),
                    user.username(), PASSWORD, "openid profile");
            final JWTClaimsSet id = oidc.verify(tokens.idToken());
            assertThat(id.getIssuer()).isEqualTo(baseUrl() + "/realms/" + web.realmId());
            assertThat(id.getSubject()).isEqualTo(user.userId());
        }
        // Realm A's secret does not authenticate realm B's client of the same name.
        final E2eHttp.Response cross = oidc(realmB).tokenEndpoint(clientId, webA.secret(),
                Map.of("grant_type", "client_credentials"));
        assertThat(cross.status()).as(cross.toString()).isEqualTo(401);
    }

    @Test
    void clientCreatedThroughTheAdminApi_isBoundToThePathRealm() {
        final String realm = E2eSeed.unique("firm-c");
        seed().realm(realm);
        final String clientId = E2eSeed.unique("portal");
        final E2eHttp.Response created = adminSession(realm).post("/admin/realms/" + realm + "/clients",
                Map.of("clientId", clientId, "grantTypes", List.of("client_credentials"),
                        "scopes", List.of("api.read")));
        assertThat(created.status()).as(created.toString()).isBetween(200, 201);
        assertThat(context.getBean(ServiceProviderRepository.class).findByClientIdAndRealmIdAndDeleted(clientId, realm, false))
                .as("client %s in realm %s", clientId, realm).isPresent();
    }

    @Test
    void realmAdmin_cannotReachAnotherRealmsClientById() {
        final String realmA = E2eSeed.unique("firm-d");
        final String realmB = E2eSeed.unique("firm-e");
        seed().realm(realmA);
        seed().realm(realmB);
        final E2eSeed.SeededClient other = seed().confidentialClient(realmB, E2eSeed.unique("ledger"), List.of("openid"));
        final E2eAdminSession adminA = adminSession(realmA);
        final String viaA = "/admin/realms/" + realmA + "/clients/" + other.id();

        assertThat(adminA.get(viaA).status()).isEqualTo(404);
        assertThat(adminA.get(viaA + "/secret").status()).isEqualTo(404);
        assertThat(adminA.post(viaA + "/secret", Map.of()).status()).isEqualTo(404);
        assertThat(adminA.put(viaA, Map.of("clientId", other.clientId(), "redirectUris", List.of("https://evil.example/cb")))
                .status()).isEqualTo(404);
        assertThat(adminA.delete(viaA).status()).isEqualTo(404);
        // Untouched: realm B's client still authenticates with its original secret.
        assertThat(oidc(realmB).tokenEndpoint(other.clientId(), other.secret(), Map.of("grant_type", "client_credentials"))
                .status()).isNotEqualTo(401);
    }
}
