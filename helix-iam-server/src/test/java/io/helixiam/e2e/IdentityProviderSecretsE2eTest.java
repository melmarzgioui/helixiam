/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.e2e;

import tools.jackson.databind.JsonNode;
import io.helixiam.authorization.amqp.federation.IdentityProviderConfig;
import io.helixiam.authorization.amqp.federation.IdentityProviderConfigPublisher;
import io.helixiam.authorization.amqp.federation.IdentityProviderRef;
import io.helixiam.authorization.federation.FederationProviderFactory;
import io.helixiam.authorization.federation.IdentityProviderSecretsBackfill;
import io.helixiam.authorization.federation.IdentityProviderSecretsMigrator;
import io.helixiam.authorization.federation.spi.IdentityProvider;
import io.helixiam.persistence.security.AttributeEncryption;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DataSourceUtils;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.SQLException;
import java.util.LinkedHashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Task 4 (security): identity-provider secrets (OIDC {@code clientSecret}, eID SP private keys, ...) are stored
 * encrypted in {@code identity_provider.secret_json}, never in {@code config_json}, never returned by the admin API
 * ({@code "<key>Set": true|false} instead), masked on export, and write-only: absent / blank keeps the stored value, a
 * value replaces it, {@code clear<Key>: "true"} removes it. The runtime (registry / {@code fromStored}) still sees the
 * merged map.
 */
class IdentityProviderSecretsE2eTest extends AbstractE2eTest {

    private static final String CLIENT_SECRET = "oidc-upstream-s3cret-" + "Z9q7";
    private static final String DECRYPT_KEY = "-----BEGIN PRIVATE KEY-----\nMIIEdecrypt-key-material-" + "A1b2\n-----END PRIVATE KEY-----";
    private static final String SIGN_KEY = "-----BEGIN PRIVATE KEY-----\nMIIEsign-key-material-" + "C3d4\n-----END PRIVATE KEY-----";

    private String realm;
    private E2eAdminSession admin;
    private JdbcTemplate jdbc;
    private TransactionTemplate tx;

    @BeforeEach
    void setUp() {
        realm = E2eSeed.unique("idpsec");
        seed().realm(realm);
        admin = adminSession();
        jdbc = context.getBean(JdbcTemplate.class);
        tx = new TransactionTemplate(context.getBean(PlatformTransactionManager.class));
    }

    @Test
    void oidcClientSecret_isEncryptedAtRest_neverReturned_maskedOnExport_andWriteOnly() {
        final Map<String, String> config = new LinkedHashMap<>();
        config.put("clientId", "helix");
        config.put("clientSecret", CLIENT_SECRET);
        config.put("issuer", "https://upstream.example");
        config.put("authorizationEndpoint", "https://upstream.example/authorize");
        config.put("tokenEndpoint", "https://upstream.example/token");
        config.put("jwksUri", "https://upstream.example/jwks");
        final E2eHttp.Response created = admin.post(base(), body("upstream", "oidc", config));
        assertThat(created.status()).as(created.toString()).isEqualTo(201);
        assertThat(created.body()).doesNotContain(CLIENT_SECRET);
        assertThat(created.json().path("config").path("clientSecretSet").asBoolean()).isTrue();

        // GET (by alias and list): no value, only "clientSecretSet": true.
        final JsonNode one = admin.get(base() + "/upstream").json();
        assertThat(one.path("config").has("clientSecret")).isFalse();
        assertThat(one.path("config").path("clientSecretSet").isBoolean()).isTrue();
        assertThat(one.path("config").path("clientSecretSet").asBoolean()).isTrue();
        assertThat(one.path("config").path("clientId").asText()).isEqualTo("helix");
        final E2eHttp.Response list = admin.get(base());
        assertThat(list.body()).doesNotContain(CLIENT_SECRET).contains("\"clientSecretSet\":true");

        // At rest: not in config_json, and secret_json is not plaintext.
        assertThat(column("config_json", "upstream")).doesNotContain(CLIENT_SECRET).doesNotContain("clientSecret");
        assertThat(column("secret_json", "upstream")).isNotBlank().doesNotContain(CLIENT_SECRET)
                .doesNotContain("clientSecret");

        // Export masks it.
        final E2eHttp.Response export = admin.get("/admin/realms/" + realm + "/export");
        assertThat(export.status()).as(export.toString()).isEqualTo(200);
        assertThat(export.body()).doesNotContain(CLIENT_SECRET);

        // PUT without the key keeps it; a round-tripped "clientSecretSet" is never stored.
        final Map<String, String> edit = new LinkedHashMap<>(config);
        edit.remove("clientSecret");
        edit.put("clientId", "helix-2");
        edit.put("clientSecretSet", "true");
        final E2eHttp.Response kept = admin.put(base() + "/upstream", body("upstream", "oidc", edit));
        assertThat(kept.status()).as(kept.toString()).isEqualTo(200);
        assertThat(kept.json().path("config").path("clientSecretSet").asBoolean()).isTrue();
        assertThat(column("config_json", "upstream")).contains("helix-2").doesNotContain("clientSecretSet");
        final IdentityProviderConfig runtime = runtime("upstream");
        assertThat(runtime.config()).containsEntry("clientSecret", CLIENT_SECRET).containsEntry("clientId", "helix-2");
        // The runtime still builds a working broker from the merged map (FederationProviderFactory.fromStored).
        final IdentityProvider provider = context.getBean(FederationProviderFactory.class).fromStored(runtime);
        final IdentityProvider.RedirectResponse start = provider.start(new IdentityProvider.AuthnRequestContext(
                realm, "st", baseUrl() + "/realms/" + realm + "/broker/upstream/callback"));
        assertThat(start.location()).startsWith("https://upstream.example/authorize").contains("client_id=helix-2");

        // Blank keeps too (the console sends nothing, but a blank must never wipe it).
        edit.put("clientSecret", "");
        admin.put(base() + "/upstream", body("upstream", "oidc", edit));
        assertThat(runtime("upstream").config()).containsEntry("clientSecret", CLIENT_SECRET);

        // A value replaces it.
        edit.put("clientSecret", "rotated-" + CLIENT_SECRET);
        admin.put(base() + "/upstream", body("upstream", "oidc", edit));
        assertThat(runtime("upstream").config()).containsEntry("clientSecret", "rotated-" + CLIENT_SECRET);

        // A new value together with clear is a 400 {message, fieldErrors}, and nothing changes.
        edit.put("clientSecret", "other");
        edit.put("clearClientSecret", "true");
        final E2eHttp.Response both = admin.put(base() + "/upstream", body("upstream", "oidc", edit));
        assertThat(both.status()).as(both.toString()).isEqualTo(400);
        assertThat(both.json().path("fieldErrors").has("config.clearClientSecret")).isTrue();
        assertThat(both.json().path("message").asText()).isNotBlank();
        assertThat(runtime("upstream").config()).containsEntry("clientSecret", "rotated-" + CLIENT_SECRET);

        // "" with clearClientSecret=true removes it.
        edit.put("clientSecret", "");
        final E2eHttp.Response cleared = admin.put(base() + "/upstream", body("upstream", "oidc", edit));
        assertThat(cleared.status()).as(cleared.toString()).isEqualTo(200);
        assertThat(cleared.json().path("config").path("clientSecretSet").asBoolean()).isFalse();
        assertThat(runtime("upstream").config()).doesNotContainKey("clientSecret");
        assertThat(column("config_json", "upstream")).doesNotContain("clearClientSecret");
    }

    @Test
    void eidPrivateKeys_areEncryptedAtRest_neverReturned_andKeptOnUpdate() {
        final Map<String, String> config = new LinkedHashMap<>();
        config.put("ssoUrl", "https://was-preprod1.digid.nl/saml/idp/request_authentication");
        config.put("idpEntityId", "https://was-preprod1.digid.nl/saml/idp/metadata");
        config.put("spEntityId", "https://helix.example/sp");
        config.put("spDecryptionPrivateKey", DECRYPT_KEY);
        config.put("spSigningPrivateKey", SIGN_KEY);
        final E2eHttp.Response created = admin.post(base(), body("digid", "digid", config));
        assertThat(created.status()).as(created.toString()).isEqualTo(201);
        assertThat(created.body()).doesNotContain("key-material");

        final JsonNode one = admin.get(base() + "/digid").json();
        assertThat(one.path("config").has("spDecryptionPrivateKey")).isFalse();
        assertThat(one.path("config").has("spSigningPrivateKey")).isFalse();
        assertThat(one.path("config").path("spDecryptionPrivateKeySet").asBoolean()).isTrue();
        assertThat(one.path("config").path("spSigningPrivateKeySet").asBoolean()).isTrue();

        assertThat(column("config_json", "digid")).doesNotContain("key-material").doesNotContain("PrivateKey");
        assertThat(column("secret_json", "digid")).doesNotContain("key-material").doesNotContain("PRIVATE KEY");
        assertThat(admin.get("/admin/realms/" + realm + "/export").body()).doesNotContain("key-material");

        final Map<String, String> edit = new LinkedHashMap<>(config);
        edit.remove("spDecryptionPrivateKey");
        edit.remove("spSigningPrivateKey");
        edit.put("spEntityId", "https://helix.example/sp2");
        final E2eHttp.Response kept = admin.put(base() + "/digid", body("digid", "digid", edit));
        assertThat(kept.status()).as(kept.toString()).isEqualTo(200);
        assertThat(runtime("digid").config())
                .containsEntry("spDecryptionPrivateKey", DECRYPT_KEY)
                .containsEntry("spSigningPrivateKey", SIGN_KEY)
                .containsEntry("spEntityId", "https://helix.example/sp2");

        // Clearing one key leaves the other.
        edit.put("clearSpSigningPrivateKey", "true");
        final JsonNode cleared = admin.put(base() + "/digid", body("digid", "digid", edit)).json();
        assertThat(cleared.path("config").path("spSigningPrivateKeySet").asBoolean()).isFalse();
        assertThat(cleared.path("config").path("spDecryptionPrivateKeySet").asBoolean()).isTrue();
        assertThat(runtime("digid").config()).containsEntry("spDecryptionPrivateKey", DECRYPT_KEY)
                .doesNotContainKey("spSigningPrivateKey");
    }

    @Test
    void legacyRowsWithSecretsInConfigJson_areMovedOut_idempotently() {
        final String id = realm + "|legacy";
        tx.executeWithoutResult(s -> jdbc.update("INSERT INTO identity_provider (id, realm_id, alias, protocol, "
                        + "display_name, config_json, enabled) VALUES (?, ?, 'legacy', 'oidc', 'Legacy', ?, true)", id, realm,
                "{\"clientId\":\"old\",\"clientSecret\":\"" + CLIENT_SECRET + "\"}"));
        // Before the move the runtime already sees the legacy secret, and the API never returns it.
        assertThat(runtime("legacy").config()).containsEntry("clientSecret", CLIENT_SECRET);
        assertThat(admin.get(base() + "/legacy").body()).doesNotContain(CLIENT_SECRET).contains("\"clientSecretSet\":true");

        final AttributeEncryption encryption = new AttributeEncryption("0123456789abcdef0123456789abcdef");
        assertThat(migrate(encryption)).isGreaterThanOrEqualTo(1);
        assertThat(column("config_json", "legacy")).doesNotContain(CLIENT_SECRET).contains("\"clientId\":\"old\"");
        final String secretJson = column("secret_json", "legacy");
        assertThat(secretJson).doesNotContain(CLIENT_SECRET);
        assertThat(encryption.convertToEntityAttribute(secretJson)).contains(CLIENT_SECRET);
        assertThat(runtime("legacy").config()).containsEntry("clientSecret", CLIENT_SECRET);

        // A second run changes nothing.
        assertThat(migrate(encryption)).isZero();
        assertThat(column("secret_json", "legacy")).isEqualTo(secretJson);
    }

    @Test
    void theSchemaPathRunsTheMove_flywayV75_1OrTheStartupBackfill() {
        final IdentityProviderSecretsBackfill backfill =
                context.getBeanProvider(IdentityProviderSecretsBackfill.class).getIfAvailable();
        if (backfill == null) {
            // Flyway path: the Java migration is registered and has run.
            assertThat(jdbc.queryForObject("SELECT count(*) FROM flyway_schema_history WHERE version = '75.1' "
                    + "AND success", Integer.class)).isEqualTo(1);
            return;
        }
        // schema.sql path: the startup backfill moves a legacy row.
        tx.executeWithoutResult(s -> jdbc.update("INSERT INTO identity_provider (id, realm_id, alias, protocol, "
                        + "display_name, config_json, enabled) VALUES (?, ?, 'old-ad', 'ldap', 'AD', ?, true)",
                realm + "|old-ad", realm, "{\"bindDn\":\"cn=svc\",\"bindPassword\":\"ldap-pw-" + "Q8\"}"));
        backfill.run(null);
        assertThat(column("config_json", "old-ad")).isEqualTo("{\"bindDn\":\"cn=svc\"}");
        assertThat(column("secret_json", "old-ad")).isNotBlank().doesNotContain("ldap-pw-");
        assertThat(runtime("old-ad").config()).containsEntry("bindPassword", "ldap-pw-Q8");
    }

    private int migrate(final AttributeEncryption encryption) {
        final DataSource ds = context.getBean(DataSource.class);
        final Integer moved = tx.execute(s -> {
            final Connection c = DataSourceUtils.getConnection(ds);
            try {
                return new IdentityProviderSecretsMigrator(encryption).migrate(c);
            } catch (final SQLException e) {
                throw new IllegalStateException(e);
            } finally {
                DataSourceUtils.releaseConnection(c, ds);
            }
        });
        return moved == null ? 0 : moved;
    }

    private String base() {
        return "/admin/realms/" + realm + "/identity-providers";
    }

    private static Map<String, Object> body(final String alias, final String protocol, final Map<String, String> config) {
        final Map<String, Object> body = new LinkedHashMap<>();
        body.put("alias", alias);
        body.put("protocol", protocol);
        body.put("displayName", alias);
        body.put("enabled", true);
        body.put("config", config);
        return body;
    }

    private IdentityProviderConfig runtime(final String alias) {
        return context.getBean(IdentityProviderConfigPublisher.class).get(new IdentityProviderRef(realm, alias));
    }

    private String column(final String column, final String alias) {
        final String value = jdbc.queryForObject("SELECT " + column + " FROM identity_provider WHERE realm_id = ? AND alias = ?",
                String.class, realm, alias);
        return value == null ? "" : value;
    }
}
