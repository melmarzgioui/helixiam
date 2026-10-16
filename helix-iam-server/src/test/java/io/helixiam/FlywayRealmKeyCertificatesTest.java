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
        Flyway.configure().dataSource(ds).locations("classpath:db/migration").target("85").load().migrate();
        final JdbcTemplate jdbc = new JdbcTemplate(ds);

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
        jdbc.update("INSERT INTO realm_key (key_id, realm_id, public_key, private_key) VALUES ('k-d', 'acme', 'p', 'q')");
        assertThat(jdbc.queryForObject("SELECT source FROM realm_key WHERE key_id = 'k-d'", String.class))
                .isEqualTo("GENERATED");
    }

    private static String b64(final byte[] b) {
        return Base64.getEncoder().encodeToString(b);
    }
}
