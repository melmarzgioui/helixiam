/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.e2e;

import com.fasterxml.jackson.databind.JsonNode;
import com.nimbusds.jwt.JWTClaimsSet;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * 1.0 item 1 (security advisory): user profile attributes must never reach a token wholesale, and never set a
 * reserved claim. Reproduction from the report: maya sets {@code attributes.sub = <joe's id>} on her own profile
 * and then logs in — before the fix her access token, id_token, userinfo and introspection all said she was joe.
 */
class ClaimInjectionE2eTest extends AbstractE2eTest {

    private static final String PASSWORD = "Cl4im-Inject-Passw0rd!";

    @Test
    void selfServiceProfileUpdate_cannotSetAReservedClaim() {
        final E2eSeed.SeededUser joe = seed().user(MASTER, E2eSeed.unique("joe"), PASSWORD);
        final E2eSeed.SeededUser maya = seed().user(MASTER, E2eSeed.unique("maya"), PASSWORD);
        final E2eAdminSession session = E2eAdminSession.login(newBrowser(), MASTER, maya.username(), PASSWORD);

        final E2eHttp.Response sub = session.put("/realms/" + MASTER + "/account/profile",
                Map.of("email", maya.username() + "@example.com", "attributes", Map.of("sub", joe.userId())));
        assertThat(sub.status()).as(sub.toString()).isEqualTo(400);
        assertThat(sub.json().path("error").asText()).isEqualTo("reserved_attribute");

        // A non-reserved attribute the realm has not allowlisted for self-service is refused too (default: none).
        final E2eHttp.Response firm = session.put("/realms/" + MASTER + "/account/profile",
                Map.of("email", maya.username() + "@example.com", "attributes", Map.of("firm", "c-joes-plumbing")));
        assertThat(firm.status()).as(firm.toString()).isEqualTo(403);
    }

    @Test
    void storedReservedAttributes_neverOverrideTokenClaims_andCustomAttributesNeedAMapper() {
        final E2eSeed.SeededUser joe = seed().user(MASTER, E2eSeed.unique("joe"), PASSWORD);
        // Simulate data already poisoned before the fix (or written by an import): reserved + custom attributes.
        final E2eSeed.SeededUser maya = seed().user(MASTER, E2eSeed.unique("maya"), PASSWORD,
                Map.of("sub", joe.userId(), "iss", "https://evil.example", "roles", "admin", "firm", "c-1"));
        final E2eSeed.SeededClient client = seed().confidentialClient(MASTER, E2eSeed.unique("ci-app"),
                List.of("openid", "profile", "email"));

        // An admin maps the custom attribute explicitly; a mapper targeting a reserved claim is refused on save.
        final E2eAdminSession admin = adminSession();
        final String mappers = "/admin/realms/" + MASTER + "/clients/" + client.clientId() + "/mappers";
        final E2eHttp.Response reserved = admin.post(mappers, Map.of("name", "evil", "mapperType", "USER_ATTRIBUTE",
                "source", "firm", "claimName", "sub", "addToAccessToken", true, "addToIdToken", true));
        assertThat(reserved.status()).as(reserved.toString()).isEqualTo(400);
        final E2eHttp.Response ok = admin.post(mappers, Map.of("name", "firm", "mapperType", "USER_ATTRIBUTE",
                "source", "firm", "claimName", "firm_id", "addToAccessToken", true, "addToIdToken", true));
        assertThat(ok.status()).as(ok.toString()).isEqualTo(201);

        final OidcFlow oidc = oidc(MASTER);
        final OidcFlow.Tokens tokens = oidc.authorizationCode(client.clientId(), client.secret(), client.redirectUri(),
                maya.username(), PASSWORD, "openid profile email");

        final JWTClaimsSet access = oidc.verify(tokens.accessToken());
        final JWTClaimsSet id = oidc.verify(tokens.idToken());
        assertThat(access.getSubject()).isEqualTo(maya.userId());
        assertThat(id.getSubject()).isEqualTo(maya.userId());
        assertThat(access.getIssuer()).isEqualTo(oidc.issuer());
        assertThat(id.getIssuer()).isEqualTo(oidc.issuer());
        assertThat(access.getClaims()).doesNotContainKey("firm");
        assertThat(id.getClaims()).doesNotContainKey("firm");
        assertThat(access.getClaim("firm_id")).isEqualTo("c-1");
        assertThat(access.getClaim("roles")).isNotEqualTo("admin");

        final E2eHttp.Response userinfo = oidc.userinfo(tokens.accessToken());
        assertThat(userinfo.status()).as(userinfo.toString()).isEqualTo(200);
        assertThat(userinfo.json().path("sub").asText()).isEqualTo(maya.userId());
        assertThat(userinfo.json().has("firm")).isFalse();

        final JsonNode introspection = oidc.introspect(client.clientId(), client.secret(), tokens.accessToken());
        assertThat(introspection.path("active").asBoolean()).as(introspection.toString()).isTrue();
        assertThat(introspection.path("sub").asText()).isEqualTo(maya.userId());
        assertThat(introspection.path("iss").asText()).isEqualTo(oidc.issuer());
    }
}
