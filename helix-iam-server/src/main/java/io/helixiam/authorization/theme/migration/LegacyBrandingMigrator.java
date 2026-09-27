/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.theme.migration;

import io.helixiam.authorization.theme.CustomCssValidator;
import io.helixiam.authorization.theme.LocalizedText;
import io.helixiam.authorization.theme.Theme;
import io.helixiam.authorization.theme.ThemeAssets;
import io.helixiam.authorization.theme.ThemeColor;
import io.helixiam.authorization.theme.ThemeColorMath;
import io.helixiam.authorization.theme.ThemeColors;
import io.helixiam.authorization.theme.ThemeJson;
import io.helixiam.authorization.theme.ThemeMerger;
import io.helixiam.authorization.theme.ThemeTexts;
import io.helixiam.authorization.theme.ThemeUrls;
import io.helixiam.authorization.theme.ThemeValidator;
import io.helixiam.common.log.LogSafe;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.function.Consumer;

/**
 * Moves the legacy branding columns into the theme layers (spec §7 migration). Shared by the Flyway Java migration
 * ({@link V20__Migrate_legacy_branding}) and, on the {@code schema.sql} path, {@link LegacyBrandingBackfill}.
 *
 * <ul>
 *   <li>{@code realm_config}: {@code primary_color} → {@code colors.primary.light}, {@code background_color} →
 *       {@code colors.surface.light}, {@code logo_url} → {@code assets.logoUrl}, {@code welcome_text} →
 *       {@code texts.welcomeText}, {@code custom_css} → {@code customCss} (kept only if it passes
 *       {@link CustomCssValidator}; its {@code url()}s may use only the operator-configured image origins).</li>
 *   <li>{@code organization}: {@code logo_url}, {@code primary_color} → the organization layer.</li>
 * </ul>
 *
 * Every value that does not meet the new rules is dropped and reported through the warning sink (by default the
 * log) naming the realm/organization, the field and the reason. Contrast is not enforced on migrated data. Values a
 * layer already sets win over the legacy ones. The legacy columns are emptied afterwards, so the run is idempotent.
 */
public final class LegacyBrandingMigrator {

    private static final org.apache.logging.log4j.Logger LOG =
            org.apache.logging.log4j.LogManager.getLogger(LegacyBrandingMigrator.class);

    /** How many layers were written. */
    public record Result(int realms, int organizations) {
    }

    private final Set<String> allowedImageOrigins;
    private final Consumer<String> warnings;

    public LegacyBrandingMigrator(final Set<String> allowedImageOrigins, final Consumer<String> warnings) {
        this.allowedImageOrigins = allowedImageOrigins == null ? Set.of() : Set.copyOf(allowedImageOrigins);
        this.warnings = warnings == null ? LegacyBrandingMigrator::logWarning : warnings;
    }

    private static void logWarning(final String message) {
        LOG.warn("{}", LogSafe.sanitize(message));
    }

    public Result migrate(final Connection c) throws SQLException {
        return new Result(migrateRealms(c), migrateOrganizations(c));
    }

    private int migrateRealms(final Connection c) throws SQLException {
        final List<String[]> rows = new ArrayList<>();
        try (PreparedStatement ps = c.prepareStatement("SELECT realm_id, logo_url, primary_color, background_color, "
                + "welcome_text, custom_css FROM realm_config WHERE logo_url IS NOT NULL OR primary_color IS NOT NULL "
                + "OR background_color IS NOT NULL OR welcome_text IS NOT NULL OR custom_css IS NOT NULL");
             ResultSet rs = ps.executeQuery()) {
            while (rs.next()) {
                rows.add(new String[] {rs.getString(1), rs.getString(2), rs.getString(3), rs.getString(4),
                        rs.getString(5), rs.getString(6)});
            }
        }
        int written = 0;
        for (final String[] r : rows) {
            final String realm = r[0];
            final String owner = "Realm " + realm;
            final String logo = url(owner, realm, "logoUrl", r[1]);
            final String primary = colour(owner, "primaryColor", r[2]);
            final String background = colour(owner, "backgroundColor", r[3]);
            final String welcome = text(owner, "welcomeText", r[4]);
            final String css = css(realm, r[5]);
            final Theme legacy = layer(logo, primary, background, welcome, css);
            if (!legacy.isEmpty()) {
                final Theme existing = ThemeJson.read(select(c, "SELECT theme_json FROM realm_theme WHERE realm_id = ?", realm));
                upsert(c, "INSERT INTO realm_theme (realm_id, theme_json, updated_at) VALUES (?, ?, CURRENT_TIMESTAMP) "
                        + "ON CONFLICT (realm_id) DO UPDATE SET theme_json = EXCLUDED.theme_json, updated_at = CURRENT_TIMESTAMP",
                        realm, ThemeJson.write(ThemeMerger.merge(legacy, existing)));
                written++;
            }
            try (PreparedStatement ps = c.prepareStatement("UPDATE realm_config SET logo_url = NULL, primary_color = NULL, "
                    + "background_color = NULL, welcome_text = NULL, custom_css = NULL WHERE realm_id = ?")) {
                ps.setString(1, realm);
                ps.executeUpdate();
            }
        }
        return written;
    }

    private int migrateOrganizations(final Connection c) throws SQLException {
        final List<String[]> rows = new ArrayList<>();
        try (PreparedStatement ps = c.prepareStatement("SELECT org_id, tenant_id, logo_url, primary_color FROM organization "
                + "WHERE logo_url IS NOT NULL OR primary_color IS NOT NULL");
             ResultSet rs = ps.executeQuery()) {
            while (rs.next()) {
                rows.add(new String[] {rs.getString(1), rs.getString(2), rs.getString(3), rs.getString(4)});
            }
        }
        int written = 0;
        for (final String[] r : rows) {
            final String owner = "Organization " + r[0] + " (realm " + r[1] + ")";
            final Theme legacy = layer(url(owner, r[1], "logoUrl", r[2]), colour(owner, "primaryColor", r[3]), null, null, null);
            if (!legacy.isEmpty()) {
                final Theme existing = ThemeJson.read(select(c, "SELECT theme_json FROM organization_theme WHERE org_id = ?", r[0]));
                try (PreparedStatement ps = c.prepareStatement("INSERT INTO organization_theme (org_id, realm_id, theme_json, "
                        + "updated_at) VALUES (?, ?, ?, CURRENT_TIMESTAMP) ON CONFLICT (org_id) DO UPDATE SET "
                        + "theme_json = EXCLUDED.theme_json, updated_at = CURRENT_TIMESTAMP")) {
                    ps.setString(1, r[0]);
                    ps.setString(2, r[1]);
                    ps.setString(3, ThemeJson.write(ThemeMerger.merge(legacy, existing)));
                    ps.executeUpdate();
                }
                written++;
            }
            try (PreparedStatement ps = c.prepareStatement(
                    "UPDATE organization SET logo_url = NULL, primary_color = NULL WHERE org_id = ?")) {
                ps.setString(1, r[0]);
                ps.executeUpdate();
            }
        }
        return written;
    }

    private static Theme layer(final String logo, final String primary, final String background, final String welcome,
                               final String css) {
        final ThemeColors colors = primary == null && background == null ? null : ThemeColors.from(role -> switch (role) {
            case "primary" -> primary == null ? null : ThemeColor.of(primary);
            case "surface" -> background == null ? null : ThemeColor.of(background);
            default -> null;
        });
        return new Theme(colors, null, null, logo == null ? null : new ThemeAssets(logo, null, null, null), null,
                welcome == null ? null : new ThemeTexts(null, null, null, LocalizedText.of(welcome), null, null),
                null, css);
    }

    private String colour(final String owner, final String field, final String value) {
        if (blank(value)) {
            return null;
        }
        final String v = value.trim();
        if (ThemeColorMath.isHex(v)) {
            return v;
        }
        drop(owner, field, "not a #RRGGBB colour");
        return null;
    }

    private String url(final String owner, final String realm, final String field, final String value) {
        if (blank(value)) {
            return null;
        }
        final String v = value.trim();
        if (ThemeUrls.isHttps(v) || ThemeUrls.parseAsset(v).filter(a -> a.realmId().equals(realm)).isPresent()) {
            return v;
        }
        drop(owner, field, "not an https URL");
        return null;
    }

    private String text(final String owner, final String field, final String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        final String problem = ThemeValidator.plainText(value, 500);
        if (problem != null) {
            drop(owner, field, problem);
            return null;
        }
        return value;
    }

    /** Legacy CSS is kept only if it passes the validator; url() may use the OPERATOR allowlist only. */
    private String css(final String realm, final String value) {
        if (blank(value)) {
            return null;
        }
        final List<String> problems = CustomCssValidator.problems(value, realm, allowedImageOrigins);
        if (!problems.isEmpty()) {
            warnings.accept("Realm " + realm + ": legacy custom CSS dropped during the theme migration and will not be "
                    + "served: " + problems.get(0));
            return null;
        }
        return value.strip();
    }

    private void drop(final String owner, final String field, final String reason) {
        warnings.accept(owner + ": legacy branding " + field + " dropped during the theme migration: " + reason);
    }

    private static String select(final Connection c, final String sql, final String id) throws SQLException {
        try (PreparedStatement ps = c.prepareStatement(sql)) {
            ps.setString(1, id);
            try (ResultSet rs = ps.executeQuery()) {
                return rs.next() ? rs.getString(1) : null;
            }
        }
    }

    private static void upsert(final Connection c, final String sql, final String id, final String json) throws SQLException {
        try (PreparedStatement ps = c.prepareStatement(sql)) {
            ps.setString(1, id);
            ps.setString(2, json);
            ps.executeUpdate();
        }
    }

    private static boolean blank(final String v) {
        return v == null || v.isBlank();
    }
}
