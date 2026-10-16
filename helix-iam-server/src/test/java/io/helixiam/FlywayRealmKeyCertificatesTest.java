/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam;

import io.helixiam.authorization.service.key.RealmKeyMaterial;
import io.helixiam.persistence.security.AttributeEncryption;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.util.Base64;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * V86 (bring-your-own realm keys): rc.11 {@code realm_key} rows (algorithm {@code RSA}, no certificate) migrate to
 * algorithm RS256, source GENERATED, no chain, status unchanged — and still load and sign afterwards (rolling upgrade).
 */
@Testcontainers
class FlywayRealmKeyCertificatesTest {

    @Container
    @SuppressWarnings("resource")
    static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>("postgres:16-alpine");

    private static final String DB_KEY = "0123456789abcdef0123456789abcdef";

    @Test
    void v86_migratesRc11Rows_andTheyStillSign() throws Exception {
        final DriverManagerDataSource ds = new DriverManagerDataSource(POSTGRES.getJdbcUrl(), POSTGRES.getUsername(),
                POSTGRES.getPassword());
        final JdbcTemplate jdbc = new JdbcTemplate(ds);
        jdbc.execute("DROP SCHEMA public CASCADE");
        jdbc.execute("CREATE SCHEMA public");
        Flyway.configure().dataSource(ds).locations("classpath:db/migration").target("85").load().migrate();

        // Two rows exactly as rc.11 wrote them: the column default ('RSA') and an explicit 'RSA'.
        final KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
        g.initialize(2048);
        final KeyPair active = g.generateKeyPair();
        final KeyPair rotated = g.generateKeyPair();
        final AttributeEncryption enc = new AttributeEncryption(DB_KEY);
        jdbc.update("INSERT INTO realm_key (key_id, realm_id, public_key, private_key, status) VALUES (?, ?, ?, ?, ?)",
                "k-active", "acme", b64(active.getPublic().getEncoded()),
                enc.convertToDatabaseColumn(b64(active.getPrivate().getEncoded())), "ACTIVE");
        jdbc.update("INSERT INTO realm_key (key_id, realm_id, algorithm, public_key, private_key, status, rotated_date)"
                        + " VALUES (?, ?, 'RSA', ?, ?, 'ROTATED', CURRENT_TIMESTAMP)",
                "k-rotated", "acme", b64(rotated.getPublic().getEncoded()),
                enc.convertToDatabaseColumn(b64(rotated.getPrivate().getEncoded())));

        Flyway.configure().dataSource(ds).locations("classpath:db/migration").load().migrate();

        final Map<String, Object> a = jdbc.queryForMap("SELECT * FROM realm_key WHERE key_id = 'k-active'");
        assertThat(a.get("algorithm")).isEqualTo("RS256");
        assertThat(a.get("status")).isEqualTo("ACTIVE");
        assertThat(a.get("source")).isEqualTo("GENERATED");
        assertThat(a.get("certificate_chain_pem")).isNull();
        assertThat(a.get("csr_pem")).isNull();
        assertThat(a.get("activated_date")).isNull();
        assertThat(a.get("expiry_warned_on")).isNull();
        final Map<String, Object> r = jdbc.queryForMap("SELECT * FROM realm_key WHERE key_id = 'k-rotated'");
        assertThat(r.get("algorithm")).isEqualTo("RS256");
        assertThat(r.get("status")).isEqualTo("ROTATED");

        // The migrated ACTIVE row still loads and signs; the signature verifies with the stored public key.
        final KeyPair loaded = RealmKeyMaterial.decode((String) a.get("algorithm"), (String) a.get("public_key"),
                enc.convertToEntityAttribute((String) a.get("private_key")));
        final Signature s = Signature.getInstance("SHA256withRSA");
        s.initSign(loaded.getPrivate());
        s.update("rc11".getBytes(StandardCharsets.UTF_8));
        final byte[] sig = s.sign();
        final Signature v = Signature.getInstance("SHA256withRSA");
        v.initVerify(active.getPublic());
        v.update("rc11".getBytes(StandardCharsets.UTF_8));
        assertThat(v.verify(sig)).isTrue();
        assertThat(RealmKeyMaterial.kid(loaded.getPublic())).isEqualTo(RealmKeyMaterial.kid(active.getPublic()));

        // New rows default to RS256 / GENERATED; a PENDING row with a chain fits.
        jdbc.update("INSERT INTO realm_key (key_id, realm_id, public_key, private_key, status, certificate_chain_pem, "
                + "source) VALUES ('k-new', 'acme', 'p', 'q', 'PENDING', 'PEM', 'IMPORTED')");
        assertThat(jdbc.queryForObject("SELECT algorithm FROM realm_key WHERE key_id = 'k-new'", String.class))
                .isEqualTo("RS256");
        jdbc.update("INSERT INTO realm_key (key_id, realm_id, public_key, private_key) VALUES ('k-d', 'acme', 'p2', 'q')");
        assertThat(jdbc.queryForObject("SELECT source FROM realm_key WHERE key_id = 'k-d'", String.class))
                .isEqualTo("GENERATED");

        // The same public key cannot be stored twice (any realm).
        org.assertj.core.api.Assertions.assertThatThrownBy(() -> jdbc.update("INSERT INTO realm_key (key_id, realm_id, "
                + "public_key, private_key) VALUES ('k-dup', 'other', 'p', 'q')"))
                .isInstanceOf(org.springframework.dao.DuplicateKeyException.class);
        // Signing settings: optional per realm, RS256 by default.
        jdbc.update("INSERT INTO realm_signing_settings (realm_id) VALUES ('acme')");
        assertThat(jdbc.queryForMap("SELECT default_alg, saml_alg FROM realm_signing_settings WHERE realm_id = 'acme'"))
                .containsEntry("default_alg", "RS256").containsEntry("saml_alg", "RS256");
    }

    @Test
    void v86_deduplicatesRc11FirstUseRaces_beforeTheUniqueIndex() throws Exception {
        final PostgreSQLContainer<?> db = POSTGRES;
        final DriverManagerDataSource ds = new DriverManagerDataSource(db.getJdbcUrl(), db.getUsername(), db.getPassword());
        final JdbcTemplate jdbc = new JdbcTemplate(ds);
        jdbc.execute("DROP SCHEMA public CASCADE");
        jdbc.execute("CREATE SCHEMA public");
        Flyway.configure().dataSource(ds).locations("classpath:db/migration").target("85").load().migrate();
        final KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
        g.initialize(2048);
        final String pubA = b64(g.generateKeyPair().getPublic().getEncoded());
        final String pubB = b64(g.generateKeyPair().getPublic().getEncoded());
        // rc.11: two concurrent first-use requests stored the same key twice (both ACTIVE), and an older duplicate.
        final String insert = "INSERT INTO realm_key (key_id, realm_id, public_key, private_key, status, creation_date) "
                + "VALUES (?, 'acme', ?, 'x', ?, ?)";
        jdbc.update(insert, "a-old", pubA, "ROTATED", java.sql.Timestamp.valueOf("2026-01-01 00:00:00"));
        jdbc.update(insert, "a-active", pubA, "ACTIVE", java.sql.Timestamp.valueOf("2026-01-02 00:00:00"));
        jdbc.update(insert, "a-active2", pubA, "ACTIVE", java.sql.Timestamp.valueOf("2026-01-02 00:00:01"));
        jdbc.update(insert, "b-1", pubB, "ROTATED", java.sql.Timestamp.valueOf("2026-01-01 00:00:00"));
        jdbc.update(insert, "b-2", pubB, "RETIRED", java.sql.Timestamp.valueOf("2026-02-01 00:00:00"));

        Flyway.configure().dataSource(ds).locations("classpath:db/migration").load().migrate();

        assertThat(jdbc.queryForList("SELECT key_id FROM realm_key WHERE public_key = ?", String.class, pubA))
                .containsExactly("a-active2"); // an ACTIVE row, the newest
        assertThat(jdbc.queryForList("SELECT key_id FROM realm_key WHERE public_key = ?", String.class, pubB))
                .containsExactly("b-2"); // no ACTIVE row: the newest
        // Idempotent: running the dedupe again changes nothing.
        Flyway.configure().dataSource(ds).locations("classpath:db/migration").load().migrate();
        assertThat(jdbc.queryForObject("SELECT count(*) FROM realm_key", Integer.class)).isEqualTo(2);
    }

    @Test
    void v86_grandfathersExistingFederatedLinks_andPlacesThemInARealm() throws Exception {
        final PostgreSQLContainer<?> db = POSTGRES;
        final DriverManagerDataSource ds = new DriverManagerDataSource(db.getJdbcUrl(), db.getUsername(), db.getPassword());
        final JdbcTemplate jdbc = new JdbcTemplate(ds);
        jdbc.execute("DROP SCHEMA public CASCADE");
        jdbc.execute("CREATE SCHEMA public");
        Flyway.configure().dataSource(ds).locations("classpath:db/migration").target("85").load().migrate();
        final String user = "INSERT INTO user_credentials (user_id, username, realm_id, creation_date) VALUES (?, ?, ?, ?)";
        jdbc.update(user, "u-a", "ada", "acme", java.sql.Timestamp.valueOf("2026-01-01 10:00:00"));
        jdbc.update(user, "u-b", "bob", "beta", java.sql.Timestamp.valueOf("2025-01-01 10:00:00"));
        final String idp = "INSERT INTO identity_provider (id, realm_id, alias, protocol, config_json) VALUES (?, ?, ?, ?, '{}')";
        // "corp" exists in two realms; "wallet" and "okta" in one each.
        jdbc.update(idp, "acme|corp", "acme", "corp", "oidc");
        jdbc.update(idp, "beta|corp", "beta", "corp", "oidc");
        jdbc.update(idp, "acme|wallet", "acme", "wallet", "eudi-wallet");
        jdbc.update(idp, "beta|okta", "beta", "okta", "oidc");
        final String link = "INSERT INTO federated_link (id, idp_alias, external_subject, user_id) VALUES (?, ?, ?, ?)";
        jdbc.update(link, "corp|a", "corp", "a", "u-a");
        jdbc.update(link, "corp|b", "corp", "b", "u-b");
        jdbc.update(link, "wallet|c", "wallet", "c", "u-b");
        jdbc.update(link, "okta|d", "okta", "d", "u-a");

        Flyway.configure().dataSource(ds).locations("classpath:db/migration").load().migrate();

        final java.util.Map<String, String> realms = new java.util.HashMap<>();
        final java.util.Map<String, String> via = new java.util.HashMap<>();
        final java.util.Map<String, String> ids = new java.util.HashMap<>();
        jdbc.query("SELECT id, realm_id, external_subject, created_via FROM federated_link", rs -> {
            realms.put(rs.getString("external_subject"), rs.getString("realm_id"));
            via.put(rs.getString("external_subject"), rs.getString("created_via"));
            ids.put(rs.getString("external_subject"), rs.getString("id"));
        });
        // An alias in two realms falls back to the user's home realm; an alias of one realm is that realm.
        assertThat(realms).containsEntry("a", "acme").containsEntry("b", "beta").containsEntry("c", "acme")
                .containsEntry("d", "beta");
        assertThat(ids).containsEntry("a", "acme|corp|a").containsEntry("d", "beta|okta|d");
        // Grandfathered: every pre-upgrade link keeps signing its user in (LEGACY), wallet links are WALLET.
        assertThat(via).containsEntry("a", "LEGACY").containsEntry("b", "LEGACY").containsEntry("c", "WALLET")
                .containsEntry("d", "LEGACY");
        // The same subject of the same provider may now be linked in two realms.
        jdbc.update("INSERT INTO federated_link (id, realm_id, idp_alias, external_subject, user_id, created_via) "
                + "VALUES ('beta|corp|a', 'beta', 'corp', 'a', 'u-b', 'JIT')");
    }

    @Test
    void v86_refusesTheSameKeyInTwoRealms_namingThem() throws Exception {
        final DriverManagerDataSource ds = new DriverManagerDataSource(POSTGRES.getJdbcUrl(), POSTGRES.getUsername(),
                POSTGRES.getPassword());
        final JdbcTemplate jdbc = new JdbcTemplate(ds);
        jdbc.execute("DROP SCHEMA public CASCADE");
        jdbc.execute("CREATE SCHEMA public");
        Flyway.configure().dataSource(ds).locations("classpath:db/migration").target("85").load().migrate();
        final KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
        g.initialize(2048);
        final String pub = b64(g.generateKeyPair().getPublic().getEncoded());
        jdbc.update("INSERT INTO realm_key (key_id, realm_id, public_key, private_key, status) VALUES "
                + "('x1', 'alpha', ?, 'x', 'ACTIVE'), ('x2', 'beta', ?, 'x', 'ACTIVE')", pub, pub);

        org.assertj.core.api.Assertions.assertThatThrownBy(() ->
                        Flyway.configure().dataSource(ds).locations("classpath:db/migration").load().migrate())
                .hasStackTraceContaining("more than one realm (alpha, beta)");
        // Nothing was deleted.
        assertThat(jdbc.queryForObject("SELECT count(*) FROM realm_key", Integer.class)).isEqualTo(2);
    }

    private static String b64(final byte[] b) {
        return Base64.getEncoder().encodeToString(b);
    }
}
