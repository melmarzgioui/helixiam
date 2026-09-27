/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.theme.asset;

import io.helixiam.authorization.theme.RealmThemeLock;

import java.util.List;
import java.util.Optional;

/**
 * Where uploaded theme assets live (spec §3: "stored in the database, or object storage behind an interface").
 * {@link JdbcThemeAssetStore} keeps them in PostgreSQL ({@code theme_asset}, bytes in a {@code bytea}); an object
 * storage implementation can replace it later. Every lookup is scoped to a realm: an id of another realm is
 * "not found". Metadata reads never load the bytes.
 */
public interface ThemeAssetStore extends RealmThemeLock {

    /**
     * Serialises asset and theme writes of one realm for the rest of the current transaction, so the per-realm count
     * limits hold under concurrent uploads and a theme is never validated against an asset being deleted.
     */
    @Override
    void lockRealm(String realmId);

    /** Stores a new asset (its id is new). */
    void save(ThemeAssetMetadata metadata, byte[] content);

    /** The realm's assets, oldest first. */
    List<ThemeAssetMetadata> list(String realmId);

    /** One asset of the realm. */
    Optional<ThemeAssetMetadata> find(String realmId, String assetId);

    /** The bytes of one asset of the realm. */
    Optional<byte[]> content(String realmId, String assetId);

    /** Deletes one asset of the realm; false when the realm has no such asset. */
    boolean delete(String realmId, String assetId);

    /** How many assets of {@code kind} the realm has. */
    int count(String realmId, ThemeAssetKind kind);

    /** True when the realm has at least one font file with exactly this family name. */
    boolean hasFont(String realmId, String name);
}
