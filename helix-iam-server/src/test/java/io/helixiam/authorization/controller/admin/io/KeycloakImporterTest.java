package io.helixiam.authorization.controller.admin.io;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.JsonNode;
import io.helixiam.authorization.amqp.client.ClientDto;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Helix IAM PROD-5 (Keycloak importer): translates a Keycloak realm-export JSON into Helix's own
 * {@link RealmExportDocument}, which the existing {@link RealmImportService} then upserts. This test
 * pins the mapping of the high-value, cleanly-portable slices — OIDC clients (incl. grant-type
 * derivation), realm roles, and identity providers. Realm settings are intentionally left to the target
 * realm (null slice) and users come via SCIM/LDAP/bulk-import (Keycloak password hashes aren't portable).
 */
class KeycloakImporterTest {

    private static final ObjectMapper M = new ObjectMapper();

    private JsonNode kc(final String json) throws Exception {
        return M.readTree(json);
    }

    @Test
    void mapsOidcClientsWithDerivedGrantTypes() throws Exception {
        final RealmExportDocument doc = KeycloakImporter.translate(kc("""
            {
              "realm": "shop",
              "clients": [
                { "clientId": "webapp", "name": "Web App", "enabled": true, "protocol": "openid-connect",
                  "publicClient": false, "standardFlowEnabled": true, "consentRequired": true,
                  "redirectUris": ["https://app/cb"], "webOrigins": ["https://app"],
                  "rootUrl": "https://app", "baseUrl": "https://app/home",
                  "defaultClientScopes": ["openid","profile","email"] },
                { "clientId": "spa", "protocol": "openid-connect", "publicClient": true,
                  "standardFlowEnabled": true, "redirectUris": ["https://spa/cb"] },
                { "clientId": "svc", "protocol": "openid-connect", "publicClient": false,
                  "standardFlowEnabled": false, "serviceAccountsEnabled": true,
                  "directAccessGrantsEnabled": true }
              ]
            }
            """));

        assertThat(doc.realm()).isNull();         // realm settings left to the target
        assertThat(doc.clients()).hasSize(3);

        final ClientDto webapp = byId(doc, "webapp");
        assertThat(webapp.name()).isEqualTo("Web App");
        assertThat(webapp.publicClient()).isFalse();
        assertThat(webapp.grantTypes()).contains("authorization_code", "refresh_token");
        assertThat(webapp.tokenEndpointAuthMethod()).isEqualTo("CLIENT_SECRET_BASIC");
        assertThat(webapp.consentRequired()).isTrue();
        assertThat(webapp.redirectUris()).containsExactly("https://app/cb");
        assertThat(webapp.webOrigins()).containsExactly("https://app");
        assertThat(webapp.scopes()).contains("openid", "profile", "email");

        final ClientDto spa = byId(doc, "spa");
        assertThat(spa.publicClient()).isTrue();
        assertThat(spa.tokenEndpointAuthMethod()).isNull();           // public client: no secret auth
        assertThat(spa.grantTypes()).contains("authorization_code");

        final ClientDto svc = byId(doc, "svc");
        assertThat(svc.grantTypes()).contains("client_credentials", "password");
        assertThat(svc.grantTypes()).doesNotContain("authorization_code");
    }

    @Test
    void mapsRealmRolesAndIdentityProviders() throws Exception {
        final RealmExportDocument doc = KeycloakImporter.translate(kc("""
            {
              "realm": "shop",
              "roles": { "realm": [ {"name":"admin","description":"Admins"}, {"name":"user"} ] },
              "identityProviders": [
                { "alias": "google", "providerId": "google", "enabled": true, "displayName": "Google",
                  "config": { "clientId": "g-id", "clientSecret": "g-secret" } },
                { "alias": "corp-saml", "providerId": "saml", "enabled": false,
                  "config": { "singleSignOnServiceUrl": "https://idp/sso" } }
              ]
            }
            """));

        assertThat(doc.roles()).extracting("name").containsExactlyInAnyOrder("admin", "user");

        assertThat(doc.identityProviders()).hasSize(2);
        final var google = doc.identityProviders().stream().filter(p -> p.alias().equals("google")).findFirst().orElseThrow();
        assertThat(google.protocol()).isEqualTo("oidc");            // google → OIDC family
        assertThat(google.enabled()).isTrue();
        assertThat(google.displayName()).isEqualTo("Google");
        assertThat(google.config()).containsEntry("clientId", "g-id");

        final var saml = doc.identityProviders().stream().filter(p -> p.alias().equals("corp-saml")).findFirst().orElseThrow();
        assertThat(saml.protocol()).isEqualTo("saml");
        assertThat(saml.enabled()).isFalse();
    }

    @Test
    void skipsSamlClientsAndEmptySlicesGracefully() throws Exception {
        final RealmExportDocument doc = KeycloakImporter.translate(kc("""
            { "realm": "x", "clients": [ {"clientId":"sp","protocol":"saml"} ] }
            """));
        // v1 imports OIDC clients only; a SAML client is skipped, leaving no clients and null slices.
        assertThat(doc.clients()).isNull();
        assertThat(doc.roles()).isNull();
        assertThat(doc.identityProviders()).isNull();
    }

    private ClientDto byId(final RealmExportDocument doc, final String clientId) {
        return doc.clients().stream().filter(c -> c.clientId().equals(clientId)).findFirst().orElseThrow();
    }
}
