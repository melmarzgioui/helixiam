/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.theme.asset;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.stereotype.Repository;

import java.sql.Timestamp;
import java.util.List;
import java.util.Optional;

/**
 * {@link ThemeAssetStore} in PostgreSQL: table {@code theme_asset} (Flyway V21 / {@code schema.sql}), bytes in a
 * {@code bytea} column that only {@link #content} reads. Writes run inside the caller's transaction (the pool has
 * auto-commit off; {@link ThemeAssetService} is transactional).
 */
@Repository
public class JdbcThemeAssetStore implements ThemeAssetStore {

    private static final String COLUMNS = "asset_id, realm_id, kind, name, extension, content_type, font_weight, "
            + "font_style, size_bytes, sha256, created_at";

    private static final RowMapper<ThemeAssetMetadata> METADATA = (rs, i) -> {
        final Timestamp created = rs.getTimestamp("created_at");
        return new ThemeAssetMetadata(rs.getString("asset_id"), rs.getString("realm_id"),
                ThemeAssetKind.fromKey(rs.getString("kind")), rs.getString("name"), rs.getString("extension"),
                rs.getString("content_type"), rs.getInt("size_bytes"), rs.getString("sha256"),
                rs.getString("font_weight"), rs.getString("font_style"), created == null ? null : created.toInstant());
    };

    private final JdbcTemplate jdbc;

    public JdbcThemeAssetStore(final JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    @Override
    public void lockRealm(final String realmId) {
        jdbc.query("SELECT realm_id FROM realm_config WHERE realm_id = ? FOR UPDATE", rs -> null, realmId);
    }

    @Override
    public void save(final ThemeAssetMetadata m, final byte[] content) {
        jdbc.update("INSERT INTO theme_asset (" + COLUMNS + ", content) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                m.id(), m.realmId(), m.kind().key(), m.name(), m.ext(), m.contentType(), m.weight(), m.style(),
                m.size(), m.sha256(), m.created() == null ? null : Timestamp.from(m.created()), content);
    }

    @Override
    public List<ThemeAssetMetadata> list(final String realmId) {
        return jdbc.query("SELECT " + COLUMNS + " FROM theme_asset WHERE realm_id = ? ORDER BY created_at, asset_id",
                METADATA, realmId);
    }

    @Override
    public Optional<ThemeAssetMetadata> find(final String realmId, final String assetId) {
        return jdbc.query("SELECT " + COLUMNS + " FROM theme_asset WHERE realm_id = ? AND asset_id = ?", METADATA,
                realmId, assetId).stream().findFirst();
    }

    @Override
    public Optional<byte[]> content(final String realmId, final String assetId) {
        return jdbc.query("SELECT content FROM theme_asset WHERE realm_id = ? AND asset_id = ?",
                (rs, i) -> rs.getBytes("content"), realmId, assetId).stream().findFirst();
    }

    @Override
    public boolean delete(final String realmId, final String assetId) {
        return jdbc.update("DELETE FROM theme_asset WHERE realm_id = ? AND asset_id = ?", realmId, assetId) > 0;
    }

    @Override
    public int count(final String realmId, final ThemeAssetKind kind) {
        final Integer n = jdbc.queryForObject("SELECT count(*) FROM theme_asset WHERE realm_id = ? AND kind = ?",
                Integer.class, realmId, kind.key());
        return n == null ? 0 : n;
    }

    @Override
    public boolean hasFont(final String realmId, final String name) {
        return Boolean.TRUE.equals(jdbc.queryForObject("SELECT EXISTS (SELECT 1 FROM theme_asset WHERE realm_id = ? "
                + "AND kind = 'font' AND name = ?)", Boolean.class, realmId, name));
    }
}
