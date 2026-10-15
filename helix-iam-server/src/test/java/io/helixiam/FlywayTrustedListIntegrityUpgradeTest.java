/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam;

import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;
import io.helixiam.authorization.federation.wallet.testwallet.TestPki;
import io.helixiam.authorization.federation.wallet.trust.tl.TrustedListFixtures;
import io.helixiam.authorization.federation.wallet.trust.tl.TrustedListHealth;
import io.helixiam.authorization.federation.wallet.trust.tl.TrustedListIntegrity;
import io.helixiam.authorization.federation.wallet.trust.tl.TrustedListLoader;
import io.helixiam.authorization.federation.wallet.trust.tl.TrustedListRepository;
import io.helixiam.authorization.federation.wallet.trust.tl.TrustedListService;
import io.helixiam.authorization.federation.wallet.trust.tl.TrustedListSource;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;
import org.testcontainers.containers.PostgreSQLContainer;

import java.security.cert.X509Certificate;
import java.time.Clock;
import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * A trusted list source stored before V84 (no MACs) is never adopted: after the upgrade it is an integrity failure
 * (no anchors, refreshes refused, audited), and only an admin re-save followed by a refresh makes it healthy, the
 * stored anchors then being reloaded from the signed list (audited as well).
 */
class FlywayTrustedListIntegrityUpgradeTest {

    @Test
    @SuppressWarnings("resource")
    void aV81EraSource_isAnIntegrityFailure_untilAnAdminSavesItAgain() {
        try (PostgreSQLContainer<?> pg = new PostgreSQLContainer<>("postgres:16-alpine")) {
            pg.start();
            final HikariConfig hc = new HikariConfig();
            hc.setJdbcUrl(pg.getJdbcUrl());
            hc.setUsername(pg.getUsername());
            hc.setPassword(pg.getPassword());
            hc.setAutoCommit(false);
            try (HikariDataSource ds = new HikariDataSource(hc)) {
                Flyway.configure().dataSource(ds).locations("classpath:db/migration").target("83").load().migrate();
                final JdbcTemplate jdbc = new JdbcTemplate(ds);
                final DataSourceTransactionManager tm = new DataSourceTransactionManager(ds);
                final TestPki.Leaf signer = TrustedListFixtures.signer("Pre-V84 signer");
                final X509Certificate issuer = TestPki.create("Pre-V84 issuer").root();
                final long now = System.currentTimeMillis();
                // a source as V81-V83 stored it, with an earlier load's services and no MACs
                new TransactionTemplate(tm).executeWithoutResult(s -> jdbc.update("INSERT INTO trusted_list_source "
                        + "(id, realm_id, name, url, format, signer_certificates, service_types, accepted_statuses, "
                        + "territories, grace_hours, enabled, status, version, created_at, updated_at, services_json, "
                        + "sequence_number, next_update, last_success_at, last_attempt_at) VALUES ('legacy', 'r', 'ut', "
                        + "'https://tl.example/UT.xml', 'ETSI_119612_XML', ?, ?, '[]', '[]', 24, TRUE, 'OK', 3, ?, ?, "
                        + "'[]', 2, ?, ?, ?)", TestPki.pem(signer.certificate()),
                        "[\"" + TrustedListFixtures.PID_TYPE + "\"]", now, now, now + 86_400_000L, now, now));

                Flyway.configure().dataSource(ds).locations("classpath:db/migration").load().migrate();

                final byte[] list = TrustedListFixtures.signedXml(TrustedListFixtures.Spec.memberState("UT").sequence(3)
                        .service(TrustedListFixtures.Service.granted("Issuer", issuer)), signer);
                final List<String> audits = new ArrayList<>();
                final TrustedListService service = new TrustedListService(new TrustedListRepository(jdbc, tm),
                        new TrustedListLoader((u, r) -> list, Clock.systemUTC()),
                        (r, type, i, o, d) -> audits.add(type + ":" + d.get("reason")), Clock.systemUTC(),
                        TrustedListService.Settings.DEFAULTS,
                        TrustedListIntegrity.fromSecret("0123456789abcdef0123456789abcdef"), false);
                service.sync();
                final TrustedListSource upgraded = service.get("r", "legacy").orElseThrow();
                assertThat(service.status(upgraded)).isEqualTo(TrustedListHealth.Status.INTEGRITY);
                assertThat(service.anchors("r", List.of("ut"), List.of())).isEmpty();
                assertThat(audits).contains("TRUSTED_LIST_INTEGRITY_FAILED:INTEGRITY");

                // a refresh does not adopt it
                assertThat(service.refreshNow("r", "legacy").orElseThrow().state().lastError()).startsWith("INTEGRITY:");
                assertThat(audits).contains("TRUSTED_LIST_REFRESH_FAILED:INTEGRITY");
                assertThat(service.anchors("r", List.of("ut"), List.of())).isEmpty();

                // an admin checks the settings and saves them again; the next refresh reloads the anchors
                final TrustedListSource current = service.get("r", "legacy").orElseThrow();
                service.update("r", "legacy", current.config(), current.state().configVersion());
                final TrustedListSource after = service.refreshNow("r", "legacy").orElseThrow();

                assertThat(service.status(after)).isEqualTo(TrustedListHealth.Status.OK);
                assertThat(service.anchors("r", List.of("ut"), List.of())).containsExactly(issuer);
                assertThat(audits).contains("TRUSTED_LIST_INTEGRITY_RESET:INTEGRITY_RESET",
                        "TRUSTED_LIST_REFRESHED:null");
            }
        }
    }
}
