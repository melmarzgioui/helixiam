/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.theme.migration;

import io.helixiam.authorization.theme.Theme;
import io.helixiam.authorization.theme.ThemeJson;
import org.junit.jupiter.api.Test;
import org.springframework.core.io.ClassPathResource;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.jdbc.datasource.init.ResourceDatabasePopulator;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import static org.assertj.core.api.Assertions.assertThat;

/** The schema.sql path (Flyway off): legacy branding is moved into the theme layers at startup, idempotently. */
@Testcontainers
class LegacyBrandingBackfillTest {

    @Container
    @SuppressWarnings("resource")
    static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>("postgres:16-alpine");

    @Test
    void movesLegacyBrandingOnStartup_andDropsInvalidCss() {
        final DriverManagerDataSource ds = new DriverManagerDataSource(POSTGRES.getJdbcUrl(), POSTGRES.getUsername(),
                POSTGRES.getPassword());
        final ResourceDatabasePopulator schema = new ResourceDatabasePopulator(new ClassPathResource("schema.sql"));
        schema.setSeparator(";");
        schema.execute(ds);
        final JdbcTemplate jdbc = new JdbcTemplate(ds);
        jdbc.update("INSERT INTO tenant (tenant_id, name) VALUES ('legacy','legacy')");
        jdbc.update("INSERT INTO realm_config (realm_id, display_name, primary_color, welcome_text, custom_css) VALUES "
                + "('legacy','Legacy','#0A7D52','Hello','.a { behavior: url(x.htc) }')");

        final LegacyBrandingBackfill backfill = new LegacyBrandingBackfill(ds, new DataSourceTransactionManager(ds), "");
        backfill.run(null);
        backfill.run(null); // idempotent

        final Theme theme = ThemeJson.read(jdbc.queryForObject("SELECT theme_json FROM realm_theme WHERE realm_id = 'legacy'",
                String.class));
        assertThat(theme.colors().primary().light()).isEqualTo("#0A7D52");
        assertThat(theme.texts().welcomeText().resolve(null)).isEqualTo("Hello");
        assertThat(theme.customCss()).isNull();
        assertThat(jdbc.queryForObject("SELECT custom_css FROM realm_config WHERE realm_id = 'legacy'", String.class)).isNull();
    }
}
