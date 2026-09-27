/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.theme.file;

import io.helixiam.authorization.theme.Theme;
import io.helixiam.authorization.theme.ThemeAssets;
import io.helixiam.authorization.theme.asset.ThemeAssetKind;
import io.helixiam.authorization.theme.asset.ThemeAssetMetadata;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * A file theme that passed validation (spec §5): {@code {helix.theme.directory}/{name}/theme.json} plus its
 * {@code assets/}. Its asset references were resolved at load time to asset paths of a placeholder realm
 * ({@link #PLACEHOLDER_REALM}); {@link #forRealm(String)} rewrites them to the realm that uses the theme, so a file
 * asset is served under that realm's own {@code /realms/{realm}/theme/assets/{id}.{ext}}.
 *
 * @param name        the directory name, which is what a realm selects
 * @param template    the validated theme, asset URLs pointing at {@link #PLACEHOLDER_REALM}
 * @param assets      the theme's files by asset id
 * @param fingerprint a hash of the theme's files (changes whenever a file changes)
 */
public record FileTheme(String name, Theme template, Map<String, FileAsset> assets, String fingerprint) {

    /**
     * The realm segment asset URLs are validated with. It is not a valid realm id of a real realm in practice (it
     * starts with an underscore), and it is only ever replaced as the exact prefix {@link #PLACEHOLDER_PREFIX}.
     */
    public static final String PLACEHOLDER_REALM = "__file-theme__";
    static final String PLACEHOLDER_PREFIX = "/realms/" + PLACEHOLDER_REALM + "/theme/assets/";

    /** One file of a theme's {@code assets/}, checked with the same rules as an uploaded asset. */
    public record FileAsset(String id, String file, ThemeAssetKind kind, String name, String ext, String contentType,
                            byte[] bytes, String sha256, String weight, String style) {

        /** The asset as the realm serves it (same shape as an uploaded asset). */
        public ThemeAssetMetadata metadata(final String realmId, final Instant loaded) {
            return new ThemeAssetMetadata(id, realmId, kind, name, ext, contentType, bytes.length, sha256, weight, style,
                    loaded);
        }
    }

    public FileTheme {
        assets = Map.copyOf(assets);
    }

    /** The theme with its asset URLs pointing at {@code realmId}'s asset path. */
    public Theme forRealm(final String realmId) {
        final String prefix = "/realms/" + realmId + "/theme/assets/";
        Theme t = template;
        final ThemeAssets a = t.assets();
        if (a != null) {
            t = t.withAssets(new ThemeAssets(rewrite(a.logoUrl(), prefix), rewrite(a.logoDarkUrl(), prefix),
                    rewrite(a.faviconUrl(), prefix), rewrite(a.brandImageUrl(), prefix)));
        }
        if (t.customCss() != null) {
            t = t.withCustomCss(t.customCss().replace(PLACEHOLDER_PREFIX, prefix));
        }
        return t;
    }

    /** The asset with this id. */
    public Optional<FileAsset> asset(final String id) {
        return Optional.ofNullable(id == null ? null : assets.get(id));
    }

    /** The theme's font files. */
    public List<FileAsset> fonts() {
        return assets.values().stream().filter(f -> f.kind() == ThemeAssetKind.FONT)
                .sorted(java.util.Comparator.comparing(FileAsset::file)).toList();
    }

    private static String rewrite(final String url, final String prefix) {
        return url != null && url.startsWith(PLACEHOLDER_PREFIX) ? prefix + url.substring(PLACEHOLDER_PREFIX.length())
                : url;
    }
}
