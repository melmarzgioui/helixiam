/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.e2e;

import com.fasterxml.jackson.databind.JsonNode;
import com.nimbusds.jwt.JWTClaimsSet;
import io.helixiam.authorization.repository.ServiceProviderRepository;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Smoke test for the e2e harness: a real authorization-code + PKCE login over HTTP against the booted
 * server, then the resource-side endpoints (JWKS signature, userinfo, introspection), plus a
 * {@code client_credentials} service account and a session+CSRF admin API call.
 */
class OidcFlowSmokeE2eTest extends AbstractE2eTest {

    private static final String USER_PASSWORD = "Sm0ke-Test-Passw0rd!";

    @Test
    void authorizationCodeWithPkceInMasterRealm() {
        assertFullCodeFlow(MASTER);
    }

    /** Same flow in a freshly created realm (item 2: clients used to land in the master realm). */
    @Test
    void authorizationCodeWithPkceInNewRealm() {
        final String realm = "monthfold";
        seed().realm(realm);
        assertFullCodeFlow(realm);
    }

    @Test
    void clientCredentialsServiceAccountInMasterRealm() {
        final E2eSeed.SeededClient sa = seed().serviceAccountClient(MASTER, E2eSeed.unique("smoke-sa"), List.of("api.read"));
        final OidcFlow oidc = oidc(MASTER);

        final OidcFlow.Tokens tokens = oidc.clientCredentials(sa.clientId(), sa.secret(), "api.read");

        assertThat(tokens.accessToken()).isNotBlank();
        final JWTClaimsSet claims = oidc.verify(tokens.accessToken());
        assertThat(claims.getIssuer()).isEqualTo(oidc.issuer());
        assertThat(claims.getSubject()).isEqualTo(sa.clientId());
        assertThat(oidc.introspect(sa.clientId(), sa.secret(), tokens.accessToken()).path("active").asBoolean()).isTrue();
    }

    @Test
    void adminSessionCanCallTheAdminApi() {
        // Anonymous: /admin/** is 401 (never a 302 to the login page).
        assertThat(newBrowser().get("/admin/realms/master/clients").status()).isEqualTo(401);

        final E2eAdminSession admin = adminSession();
        final E2eHttp.Response clients = admin.get("/admin/realms/master/clients");
        assertThat(clients.status()).as(clients.toString()).isEqualTo(200);
        assertThat(clients.json().isArray()).isTrue();
    }

    private void assertFullCodeFlow(final String realm) {
        final E2eSeed.SeededClient client = seed().confidentialClient(realm, E2eSeed.unique("smoke-app"),
                List.of("openid", "profile", "email"));
        // Precondition (pinpoints item 2 instead of a confusing 404 further down): the client is bound to its realm.
        assertThat(context.getBean(ServiceProviderRepository.class).findByIdAndDeleted(client.id(), false))
                .as("client %s realm_id", client.clientId())
                .hasValueSatisfying(c -> assertThat(c.getRealmId()).isEqualTo(realm));
        final E2eSeed.SeededUser user = seed().user(realm, E2eSeed.unique("smoke-user"), USER_PASSWORD);
        final OidcFlow oidc = oidc(realm);

        final OidcFlow.Tokens tokens = oidc.authorizationCode(client.clientId(), client.secret(), client.redirectUri(),
                user.username(), user.password(), "openid profile email");

        assertThat(tokens.accessToken()).isNotBlank();
        assertThat(tokens.idToken()).isNotBlank();
        assertThat(tokens.refreshToken()).isNotBlank();

        // Issuer: request-derived, realm-prefixed, and identical in discovery + both tokens.
        final String issuer = oidc.issuer();
        assertThat(issuer).isEqualTo(baseUrl() + "/realms/" + realm);

        // Signatures verify against the realm's JWKS.
        final JWTClaimsSet access = oidc.verify(tokens.accessToken());
        final JWTClaimsSet id = oidc.verify(tokens.idToken());
        assertThat(access.getIssuer()).isEqualTo(issuer);
        assertThat(id.getIssuer()).isEqualTo(issuer);

        // sub = the user's opaque id (the principal name the login resolves to), not the username.
        assertThat(access.getSubject()).isEqualTo(user.userId());
        assertThat(id.getSubject()).isEqualTo(user.userId());
        assertThat(id.getAudience()).contains(client.clientId());

        final E2eHttp.Response userinfo = oidc.userinfo(tokens.accessToken());
        assertThat(userinfo.status()).as(userinfo.toString()).isEqualTo(200);
        assertThat(userinfo.json().path("sub").asText()).isEqualTo(user.userId());

        final JsonNode introspection = oidc.introspect(client.clientId(), client.secret(), tokens.accessToken());
        assertThat(introspection.path("active").asBoolean()).as(introspection.toString()).isTrue();

        // Unverified decode agrees with the verified claims.
        final Map<String, Object> raw = OidcFlow.claims(tokens.accessToken());
        assertThat(raw.get("sub")).isEqualTo(user.userId());
    }
}
