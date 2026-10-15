/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam;

import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * ROADMAP ("Realm deletion cleanup"): deleting a realm must take its wallet pepper
 * ({@code realm_wallet_pepper}), its verifier access-certificate signing keys ({@code verifier_signing_key}) and its
 * wallet transactions ({@code wallet_transaction}) with it, so a realm created again under the same id never
 * inherits the previous realm's pepper or verifier key (V85).
 *
 * <p>One mechanism for all three tables: the {@code realm_config_delete_wallet_secrets} trigger, not a foreign
 * key on any of them (see the V85 migration comment). All three are routinely written for a realm id that has no
 * {@code realm_config} row yet — the admin wallet/identity-provider APIs never require one, and
 * {@code JdbcWalletTransactionStore} is exercised directly by its own contract-suite tests the same way — so a
 * real FK would turn a working insert into a constraint violation. The trigger only acts on an actual
 * {@code realm_config} delete, and never touches a row whose realm_id has no matching {@code realm_config}.
 *
 * <p>Runs the real migrations: up to V80 (pre-fix), seed two realms' worth of wallet rows, then to the latest
 * version, then delete one realm and check the other's rows are untouched.
 */
@Testcontainers
class FlywayWalletRealmCascadeTest {

    @Container
    @SuppressWarnings("resource")
    static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>("postgres:16-alpine");

    @Test
    void deletingARealm_takesItsWalletPepperAndVerifierKeysAndTransactions_butLeavesOtherRealmsAlone() {
        final DriverManagerDataSource ds = new DriverManagerDataSource(POSTGRES.getJdbcUrl(), POSTGRES.getUsername(),
                POSTGRES.getPassword());
        Flyway.configure().dataSource(ds).locations("classpath:db/migration").target("80").load().migrate();
        final JdbcTemplate jdbc = new JdbcTemplate(ds);

        jdbc.update("INSERT INTO realm_config (realm_id, display_name) VALUES ('r1', 'R1'), ('r2', 'R2')");
        seedWalletRows(jdbc, "r1");
        seedWalletRows(jdbc, "r2");

        // Bring the database up to the latest migration (includes V85, the trigger-based cleanup fix).
        Flyway.configure().dataSource(ds).locations("classpath:db/migration").load().migrate();

        jdbc.update("DELETE FROM realm_config WHERE realm_id = 'r1'");

        assertThat(count(jdbc, "realm_wallet_pepper", "r1")).as("r1 pepper gone").isZero();
        assertThat(count(jdbc, "verifier_signing_key", "r1")).as("r1 verifier key gone").isZero();
        assertThat(count(jdbc, "wallet_transaction", "r1")).as("r1 wallet transaction gone").isZero();

        assertThat(count(jdbc, "realm_wallet_pepper", "r2")).as("r2 pepper untouched").isEqualTo(1);
        assertThat(count(jdbc, "verifier_signing_key", "r2")).as("r2 verifier key untouched").isEqualTo(1);
        assertThat(count(jdbc, "wallet_transaction", "r2")).as("r2 wallet transaction untouched").isEqualTo(1);
        assertThat(jdbc.queryForObject("SELECT count(*) FROM realm_config WHERE realm_id = 'r2'", Integer.class))
                .isEqualTo(1);
    }

    @Test
    void anUnprovisionedRealmCanStillWriteWalletRows_andOrphansAreLeftAlone() {
        // The trigger must never become an insert constraint: WalletAdminController / IdentityProviderAdminController
        // write a pepper/verifier key for a realm id with no realm_config row today (they live under /admin/**,
        // which RealmRoutingFilter never gates on realm existence), and JdbcWalletTransactionStore is exercised the
        // same way by its own tests. All three inserts must keep succeeding after V85.
        final DriverManagerDataSource ds = new DriverManagerDataSource(POSTGRES.getJdbcUrl(), POSTGRES.getUsername(),
                POSTGRES.getPassword());
        Flyway.configure().dataSource(ds).locations("classpath:db/migration").load().migrate();
        final JdbcTemplate jdbc = new JdbcTemplate(ds);

        // No realm_config row for 'unprovisioned' at all — every insert must succeed, none fail on a foreign key.
        seedWalletRows(jdbc, "unprovisioned");
        assertThat(count(jdbc, "realm_wallet_pepper", "unprovisioned")).isEqualTo(1);
        assertThat(count(jdbc, "verifier_signing_key", "unprovisioned")).isEqualTo(1);
        assertThat(count(jdbc, "wallet_transaction", "unprovisioned")).isEqualTo(1);

        // Deleting an unrelated realm must not touch it: the trigger only fires for the realm_id actually deleted.
        jdbc.update("INSERT INTO realm_config (realm_id, display_name) VALUES ('other', 'Other')");
        jdbc.update("DELETE FROM realm_config WHERE realm_id = 'other'");
        assertThat(count(jdbc, "realm_wallet_pepper", "unprovisioned")).as("orphan pepper left alone").isEqualTo(1);
        assertThat(count(jdbc, "verifier_signing_key", "unprovisioned")).as("orphan verifier key left alone")
                .isEqualTo(1);
        assertThat(count(jdbc, "wallet_transaction", "unprovisioned")).as("orphan wallet transaction left alone")
                .isEqualTo(1);
    }

    @Test
    void deletingARealm_takesItsTrustedListSourcesWithTheirMembersAndHighWaterMarks() {
        final DriverManagerDataSource ds = new DriverManagerDataSource(POSTGRES.getJdbcUrl(), POSTGRES.getUsername(),
                POSTGRES.getPassword());
        Flyway.configure().dataSource(ds).locations("classpath:db/migration").load().migrate();
        final JdbcTemplate jdbc = new JdbcTemplate(ds);

        jdbc.update("INSERT INTO realm_config (realm_id, display_name) VALUES ('tl1', 'TL1'), ('tl2', 'TL2')");
        seedTrustedList(jdbc, "tl1");
        seedTrustedList(jdbc, "tl2");

        jdbc.update("DELETE FROM realm_config WHERE realm_id = 'tl1'");

        assertThat(count(jdbc, "trusted_list_source", "tl1")).as("tl1 trusted list gone").isZero();
        assertThat(jdbc.queryForObject("SELECT count(*) FROM trusted_list_member WHERE source_id = 'src-tl1'",
                Integer.class)).as("tl1 members gone").isZero();
        assertThat(jdbc.queryForObject("SELECT count(*) FROM trusted_list_hwm WHERE source_id = 'src-tl1'",
                Integer.class)).as("tl1 high-water marks gone").isZero();

        assertThat(count(jdbc, "trusted_list_source", "tl2")).as("tl2 trusted list untouched").isEqualTo(1);
        assertThat(jdbc.queryForObject("SELECT count(*) FROM trusted_list_member WHERE source_id = 'src-tl2'",
                Integer.class)).as("tl2 members untouched").isEqualTo(1);
        assertThat(jdbc.queryForObject("SELECT count(*) FROM trusted_list_hwm WHERE source_id = 'src-tl2'",
                Integer.class)).as("tl2 high-water marks untouched").isEqualTo(1);
    }

    private static void seedTrustedList(final JdbcTemplate jdbc, final String realmId) {
        final String id = "src-" + realmId;
        jdbc.update("INSERT INTO trusted_list_source (id, realm_id, name, url, format, signer_certificates, "
                + "service_types, accepted_statuses, territories, grace_hours, enabled, status, version, created_at, "
                + "updated_at) VALUES (?, ?, 'eu', 'https://example.test/lotl.xml', 'ETSI_119612_XML', '[]', '[]', "
                + "'[]', '[]', 24, true, 'PENDING', 1, 0, 0)", id, realmId);
        jdbc.update("INSERT INTO trusted_list_member (source_id, member_key, location, territory, status, version) "
                + "VALUES (?, 'k', 'https://example.test/nl.xml', 'NL', 'PENDING', 1)", id);
        jdbc.update("INSERT INTO trusted_list_hwm (source_id, territory, tsl_type, sequence_number) "
                + "VALUES (?, 'NL', 'http://uri.etsi.org/TrstSvc/TrustedList/TSLType/EUgeneric', 7)", id);
    }

    private static int count(final JdbcTemplate jdbc, final String table, final String realmId) {
        return jdbc.queryForObject("SELECT count(*) FROM " + table + " WHERE realm_id = ?", Integer.class, realmId);
    }

    private static void seedWalletRows(final JdbcTemplate jdbc, final String realmId) {
        jdbc.update("INSERT INTO realm_wallet_pepper (realm_id, pepper) VALUES (?, ?)", realmId,
                "pepper-" + realmId);
        jdbc.update("INSERT INTO verifier_signing_key (realm_id, name, alg, private_key, certificate_chain_pem) "
                + "VALUES (?, 'default', 'ES256', 'key-" + realmId + "', 'chain-" + realmId + "')", realmId);
        jdbc.update("INSERT INTO wallet_transaction (transaction_id, same_device_request_hash, "
                + "cross_device_request_hash, response_hash, same_device_request, cross_device_request, response, "
                + "realm_id, status, purpose, expires_at) VALUES (?, ?, ?, ?, '{}', '{}', '{}', ?, 'PENDING', "
                + "'LOGIN', 9999999999999)",
                "tx-" + realmId, "sd-" + realmId, "cd-" + realmId, "resp-" + realmId, realmId);
    }
}
