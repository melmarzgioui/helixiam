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

    private MountedThemeAssets mounted;

    /** File-theme assets (spec §5): a realm may also use the fonts and images of the file theme it selected. */
    @org.springframework.beans.factory.annotation.Autowired(required = false)
    public void setMountedThemeAssets(final MountedThemeAssets mounted) {
        this.mounted = mounted;
    }

    @Override
    public boolean hasFont(final String realmId, final String fontName) {
        if (realmId == null || fontName == null) {
            return false;
        }
        return store.hasFont(realmId, fontName)
                || mounted != null && mounted.fonts(realmId).stream().anyMatch(m -> m.name().equals(fontName));
    }

    @Override
    public boolean hasAsset(final String realmId, final String assetId, final String extension) {
        if (realmId == null || assetId == null || extension == null) {
            return false;
        }
        return store.find(realmId, assetId).filter(m -> m.ext().equals(extension)).isPresent()
                || mounted != null && mounted.find(realmId, assetId)
                        .filter(a -> a.metadata().ext().equals(extension)).isPresent();
    }
}
