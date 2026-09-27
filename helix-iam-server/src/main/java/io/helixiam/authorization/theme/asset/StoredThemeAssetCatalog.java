/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.theme.asset;

import io.helixiam.authorization.theme.ThemeAssetCatalog;
import org.springframework.stereotype.Component;

/**
 * The {@link ThemeAssetCatalog} the theme validator uses: a font name is valid when the realm has a font file with
 * exactly that family name; an own-asset URL is valid when the realm has that asset with that extension.
 */
@Component
public class StoredThemeAssetCatalog implements ThemeAssetCatalog {

    private final ThemeAssetStore store;

    public StoredThemeAssetCatalog(final ThemeAssetStore store) {
        this.store = store;
    }

    @Override
    public boolean hasFont(final String realmId, final String fontName) {
        return realmId != null && fontName != null && store.hasFont(realmId, fontName);
    }

    @Override
    public boolean hasAsset(final String realmId, final String assetId, final String extension) {
        return realmId != null && assetId != null && extension != null
                && store.find(realmId, assetId).filter(m -> m.ext().equals(extension)).isPresent();
    }
}
