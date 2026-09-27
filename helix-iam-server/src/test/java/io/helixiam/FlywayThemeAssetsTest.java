/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam;

import io.helixiam.authorization.theme.asset.AssetFixtures;
import io.helixiam.authorization.theme.asset.JdbcThemeAssetStore;
import io.helixiam.authorization.theme.asset.ThemeAssetKind;
import io.helixiam.authorization.theme.asset.ThemeAssetMetadata;
import io.helixiam.authorization.theme.migration.V20__Migrate_legacy_branding;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.Test;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * V21 (spec §3): the {@code theme_asset} table holds uploaded fonts and images per realm (bytes in a
 * {@code bytea}); the JDBC store reads and writes it realm-scoped, and a deleted realm takes its assets along.
 */
@Testcontainers
class FlywayThemeAssetsTest {

    @Container
    @SuppressWarnings("resource")
    static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>("postgres:16-alpine");

    @Test
    void theAssetTableIsCreated_andTheStoreIsRealmScoped() {
        final DriverManagerDataSource ds = new DriverManagerDataSource(POSTGRES.getJdbcUrl(), POSTGRES.getUsername(),
                POSTGRES.getPassword());
        Flyway.configure().dataSource(ds).locations("classpath:db/migration")
                .javaMigrations(new V20__Migrate_legacy_branding(Set.of(), w -> { }))
                .load().migrate();
        final JdbcTemplate jdbc = new JdbcTemplate(ds);
        jdbc.update("INSERT INTO tenant (tenant_id, name) VALUES ('a','a'), ('b','b')");
        jdbc.update("INSERT INTO realm_config (realm_id, display_name) VALUES ('a','A'), ('b','B')");

        final JdbcThemeAssetStore store = new JdbcThemeAssetStore(jdbc);
        final byte[] font = AssetFixtures.woff2(300);
        final Instant now = Instant.now().truncatedTo(ChronoUnit.MILLIS);
        store.save(new ThemeAssetMetadata("f-1", "a", ThemeAssetKind.FONT, "Public Sans", "woff2", "font/woff2", 300,
                "ab".repeat(32), "400", "normal", now), font);
        store.save(new ThemeAssetMetadata("i-1", "a", ThemeAssetKind.IMAGE, "logo", "png", "image/png", 3,
                "cd".repeat(32), null, null, now.plusMillis(1)), new byte[] {1, 2, 3});
        store.lockRealm("a");

        assertThat(store.list("a")).extracting(ThemeAssetMetadata::id).containsExactly("f-1", "i-1");
        assertThat(store.list("b")).isEmpty();
        final ThemeAssetMetadata m = store.find("a", "f-1").orElseThrow();
        assertThat(m.kind()).isEqualTo(ThemeAssetKind.FONT);
        assertThat(m.name()).isEqualTo("Public Sans");
        assertThat(m.weight()).isEqualTo("400");
        assertThat(m.created()).isEqualTo(now);
        assertThat(store.find("b", "f-1")).isEmpty();
        assertThat(store.content("a", "f-1")).hasValueSatisfying(b -> assertThat(b).isEqualTo(font));
        assertThat(store.content("b", "f-1")).isEmpty();
        assertThat(store.count("a", ThemeAssetKind.FONT)).isEqualTo(1);
        assertThat(store.count("a", ThemeAssetKind.IMAGE)).isEqualTo(1);
        assertThat(store.hasFont("a", "Public Sans")).isTrue();
        assertThat(store.hasFont("b", "Public Sans")).isFalse();
        assertThat(store.delete("b", "i-1")).isFalse();
        assertThat(store.delete("a", "i-1")).isTrue();
        assertThat(store.find("a", "i-1")).isEmpty();

        // The database refuses a second identical font face and unknown kinds / extensions.
        assertThatThrownBy(() -> store.save(new ThemeAssetMetadata("f-2", "a", ThemeAssetKind.FONT, "Public Sans",
                "woff2", "font/woff2", 1, "ef".repeat(32), "400", "normal", now), new byte[] {1}))
                .isInstanceOf(DataIntegrityViolationException.class);
        assertThatThrownBy(() -> store.save(new ThemeAssetMetadata("f-3", "a", ThemeAssetKind.FONT, "PUBLIC SANS",
                "woff2", "font/woff2", 1, "ef".repeat(32), "400", "normal", now), new byte[] {1}))
                .as("review M3: a face is unique case-insensitively").isInstanceOf(DataIntegrityViolationException.class);
        assertThatThrownBy(() -> jdbc.update("INSERT INTO theme_asset (asset_id, realm_id, kind, name, extension, "
                + "content_type, size_bytes, sha256, content) VALUES ('x','a','script','x','js','text/javascript',1,"
                + "'00',decode('00','hex'))")).isInstanceOf(DataIntegrityViolationException.class);

        jdbc.update("DELETE FROM realm_config WHERE realm_id = 'a'");
        assertThat(jdbc.queryForObject("SELECT count(*) FROM theme_asset", Integer.class))
                .as("a deleted realm takes its assets along").isZero();
    }
}
