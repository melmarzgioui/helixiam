/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.theme.asset;

import java.util.List;
import java.util.Optional;

/**
 * Theme assets that are not uploaded but come with a base layer the realm uses (a file theme from
 * {@code helix.theme.directory}, spec §5). They are checked with the same {@link ThemeAssetRules} as uploads, served
 * under the realm's own asset path by the same endpoint with the same headers, and are read-only: the admin asset API
 * neither lists nor deletes them.
 */
public interface MountedThemeAssets {

    /** An asset of the base layer {@code realmId} uses. */
    Optional<ThemeAssetService.StoredAsset> find(String realmId, String assetId);

    /** The font files of the base layer {@code realmId} uses (as the realm serves them). */
    List<ThemeAssetMetadata> fonts(String realmId);
}
