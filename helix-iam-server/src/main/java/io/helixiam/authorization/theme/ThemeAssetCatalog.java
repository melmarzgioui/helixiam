/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.theme;

/**
 * Hook for uploaded theme assets and fonts (spec §3, plan Task 2). The theme validator asks it whether a font name
 * in {@code typography.fontSans}/{@code fontDisplay} is a font uploaded to the realm, and whether an asset URL
 * {@code /realms/{realm}/theme/assets/{id}.{ext}} refers to an existing asset of that realm.
 *
 * <p>Task 2 provides the implementation as a Spring bean (backed by its {@code ThemeAssetStore}); until then
 * {@link #NONE} applies: no fonts and no assets are uploaded, so only built-in font stacks and {@code https} URLs
 * validate.
 */
public interface ThemeAssetCatalog {

    /** No uploaded fonts or assets. */
    ThemeAssetCatalog NONE = new ThemeAssetCatalog() {
        @Override
        public boolean hasFont(final String realmId, final String fontName) {
            return false;
        }

        @Override
        public boolean hasAsset(final String realmId, final String assetId, final String extension) {
            return false;
        }
    };

    /** True when {@code fontName} is a font uploaded to {@code realmId}. */
    boolean hasFont(String realmId, String fontName);

    /** True when {@code realmId} has an uploaded asset {@code assetId} with {@code extension}. */
    boolean hasAsset(String realmId, String assetId, String extension);
}
