/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.e2e;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Review rc.3 #3: per-client sub-resources (mappers, roles, …) accept the client's internal id (as the other client
 * calls do) as well as its client_id, and an unknown client is a 404 — never a silently ignored 201.
 */
class ClientSubresourceKeyE2eTest extends AbstractE2eTest {

    @Test
    void mapperCreatedUnderTheInternalId_appliesToTokens_andUnknownClientsAre404() {
        final String realm = E2eSeed.unique("keys");
        seed().realm(realm, "Keys");
        final E2eAdminSession admin = adminSession(realm);
        final E2eSeed.SeededClient svc = seed().serviceAccountClient(realm, E2eSeed.unique("svc"), List.of("openid"));

        final E2eHttp.Response created = admin.post("/admin/realms/" + realm + "/clients/" + svc.id() + "/mappers",
                Map.of("name", "tier", "mapperType", "HARDCODED", "source", "gold", "claimName", "tier",
                        "addToAccessToken", true, "addToIdToken", false));
        assertThat(created.status()).as(created.toString()).isEqualTo(201);
        assertThat(admin.get("/admin/realms/" + realm + "/clients/" + svc.clientId() + "/mappers").json().size())
                .as("same mapper list under either key").isEqualTo(1);

        final OidcFlow oidc = oidc(realm);
        assertThat(oidc.verify(oidc.clientCredentials(svc.clientId(), svc.secret(), "openid").accessToken())
                .getClaim("tier")).isEqualTo("gold");

        final E2eHttp.Response unknown = admin.post("/admin/realms/" + realm + "/clients/no-such-client/mappers",
                Map.of("name", "x", "mapperType", "HARDCODED", "source", "x", "claimName", "x",
                        "addToAccessToken", true, "addToIdToken", false));
        assertThat(unknown.status()).as(unknown.toString()).isEqualTo(404);
        assertThat(admin.get("/admin/realms/" + realm + "/clients/no-such-client/roles").status()).isEqualTo(404);
    }
}
