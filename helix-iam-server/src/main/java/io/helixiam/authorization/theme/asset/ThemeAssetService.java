/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.theme.asset;

import io.helixiam.authorization.theme.Theme;
import io.helixiam.authorization.theme.ThemeAssets;
import io.helixiam.authorization.theme.ThemeService;
import io.helixiam.authorization.theme.ThemeTypography;
import io.helixiam.authorization.theme.ThemeUrls;
import io.helixiam.authorization.theme.ThemeValidationException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

/**
 * Uploaded theme fonts and images (spec §3): upload with the {@link ThemeAssetRules} and the per-realm count limits,
 * list, read and delete, always inside one realm.
 *
 * <p><b>Deleting a referenced asset is refused</b> ({@link ThemeAssetInUseException}, a 409 naming every
 * referencing field in the realm theme and in its organization themes). Silently dropping the reference would
 * change the live sign-in pages without the admin asking for it, and keeping a dangling reference would break the
 * page (a missing logo or font) and make the next theme save fail validation for a field the admin did not touch.
 * A font file may go while another file of the same family remains, because the family name still resolves.
 */
@Service
public class ThemeAssetService {

    private final ThemeAssetStore store;
    private final ThemeService themes;

    public ThemeAssetService(final ThemeAssetStore store, final ThemeService themes) {
        this.store = store;
        this.themes = themes;
    }

    private MountedThemeAssets mounted;

    /** File-theme assets (spec §5), served next to the uploaded ones; optional. */
    @org.springframework.beans.factory.annotation.Autowired(required = false)
    public void setMountedThemeAssets(final MountedThemeAssets mounted) {
        this.mounted = mounted;
    }

    /** An asset with its bytes. */
    public record StoredAsset(ThemeAssetMetadata metadata, byte[] bytes) {
    }

    /**
     * Checks and stores an upload.
     *
     * @throws ThemeValidationException ({@code file}, {@code name}, {@code weight}, {@code style}) when the file is
     *                                  refused or a realm limit is reached
     */
    @Transactional
    public ThemeAssetMetadata upload(final String realmId, final String filename, final byte[] bytes,
                                     final String name, final String weight, final String style) {
        final ThemeAssetRules.Accepted a = ThemeAssetRules.check(filename, bytes, name, weight, style);
        store.lockRealm(realmId);
        final int max = a.kind() == ThemeAssetKind.FONT ? ThemeAssetRules.MAX_FONTS : ThemeAssetRules.MAX_IMAGES;
        if (store.count(realmId, a.kind()) >= max) {
            throw new ThemeValidationException(Map.of("file", "This realm already has " + max
                    + (a.kind() == ThemeAssetKind.FONT ? " fonts" : " images") + ", the maximum; delete one first."));
        }
        if (a.kind() == ThemeAssetKind.FONT) {
            // Review M3: CSS family names match case-insensitively, so a family has exactly one spelling per realm
            // (theme references stay exact: they must use that spelling).
            store.list(realmId).stream()
                    .filter(m -> m.kind() == ThemeAssetKind.FONT && m.name().equalsIgnoreCase(a.name())
                            && !m.name().equals(a.name()))
                    .findFirst()
                    .ifPresent(m -> {
                        throw new ThemeValidationException(Map.of("name", "This realm already has the font family "
                                + m.name() + "; use exactly that spelling to add a face to it."));
                    });
        }
        if (a.kind() == ThemeAssetKind.FONT && store.list(realmId).stream().anyMatch(m -> m.kind() == ThemeAssetKind.FONT
                && m.name().equals(a.name()) && m.weight().equals(a.weight()) && m.style().equals(a.style()))) {
            throw new ThemeValidationException(Map.of("name", "This realm already has a font " + a.name()
                    + " with weight " + a.weight() + " and style " + a.style() + "; delete it first."));
        }
        final ThemeAssetMetadata m = new ThemeAssetMetadata(UUID.randomUUID().toString(), realmId, a.kind(), a.name(),
                a.extension(), a.contentType(), bytes.length, sha256(bytes), a.weight(), a.style(), Instant.now());
        store.save(m, bytes);
        invalidateAfterCommit(realmId);
        return m;
    }

    /** The realm's assets, oldest first (metadata only). */
    public List<ThemeAssetMetadata> list(final String realmId) {
        return store.list(realmId);
    }

    /**
     * One asset the realm serves (metadata only): an uploaded one, or a file of the file theme the realm uses
     * (spec §5; checked with the same rules at load time).
     */
    public Optional<ThemeAssetMetadata> find(final String realmId, final String assetId) {
        final Optional<ThemeAssetMetadata> uploaded = store.find(realmId, assetId);
        if (uploaded.isPresent() || mounted == null) {
            return uploaded;
        }
        return mounted.find(realmId, assetId).map(StoredAsset::metadata);
    }

    /** One asset the realm serves, with its bytes (uploaded, or from the realm's file theme). */
    public Optional<StoredAsset> content(final String realmId, final String assetId) {
        final Optional<StoredAsset> uploaded = store.find(realmId, assetId)
                .flatMap(m -> store.content(realmId, assetId).map(b -> new StoredAsset(m, b)));
        if (uploaded.isPresent() || mounted == null) {
            return uploaded;
        }
        return mounted.find(realmId, assetId);
    }

    /** Every font file the realm serves: its uploaded fonts, then those of its file theme (for theme.css). */
    public List<ThemeAssetMetadata> servedFonts(final String realmId) {
        final List<ThemeAssetMetadata> out = new ArrayList<>(store.list(realmId).stream()
                .filter(m -> m.kind() == ThemeAssetKind.FONT).toList());
        if (mounted != null) {
            out.addAll(mounted.fonts(realmId));
        }
        return out;
    }

    /**
     * Deletes an asset of the realm; empty when the realm has no such asset.
     *
     * @throws ThemeAssetInUseException when a theme of the realm still references it
     */
    @Transactional
    public Optional<ThemeAssetMetadata> delete(final String realmId, final String assetId) {
        store.lockRealm(realmId);
        final Optional<ThemeAssetMetadata> found = store.find(realmId, assetId);
        if (found.isEmpty()) {
            return Optional.empty();
        }
        final List<String> references = references(realmId, found.get());
        if (!references.isEmpty()) {
            throw new ThemeAssetInUseException(references);
        }
        store.delete(realmId, assetId);
        invalidateAfterCommit(realmId);
        return found;
    }

    /**
     * Replaces a font face with new bytes (archive import, {@code onConflict=overwrite}): the old file is deleted and
     * the new one uploaded under the same rules. The family keeps resolving, so typography references do not block
     * it; a reference to the old file's URL (custom CSS) does.
     *
     * @throws ThemeAssetInUseException when a theme references the old file by URL
     * @throws ThemeValidationException when the new file is refused
     */
    @Transactional
    public ThemeAssetMetadata replaceFont(final String realmId, final String existingId, final String filename,
                                          final byte[] bytes, final String name, final String weight,
                                          final String style) {
        store.lockRealm(realmId);
        final ThemeAssetMetadata old = store.find(realmId, existingId)
                .orElseThrow(() -> new ThemeValidationException(Map.of("file", "The font to replace no longer exists.")));
        final List<String> byUrl = references(realmId, old).stream()
                .filter(f -> !f.endsWith("typography.fontSans") && !f.endsWith("typography.fontDisplay")).toList();
        if (!byUrl.isEmpty()) {
            throw new ThemeAssetInUseException(byUrl);
        }
        store.delete(realmId, existingId);
        return upload(realmId, filename, bytes, name, weight, style);
    }

    /**
     * Compensation for an archive import whose document stage failed: removes an asset this import created, unless
     * a theme stored meanwhile references it. True when it was removed.
     */
    @Transactional
    public boolean removeIfUnreferenced(final String realmId, final String assetId) {
        try {
            return delete(realmId, assetId).isPresent();
        } catch (final ThemeAssetInUseException e) {
            return false;
        }
    }

    /** Compensation: puts back a font face an archive import replaced (same id, same bytes). */
    @Transactional
    public void restore(final ThemeAssetMetadata replacedBy, final ThemeAssetMetadata original, final byte[] bytes) {
        store.lockRealm(original.realmId());
        store.delete(replacedBy.realmId(), replacedBy.id());
        store.save(original, bytes);
        invalidateAfterCommit(original.realmId());
    }

    /**
     * The theme fields that would break without this asset: the base layers (a file theme, spec §5; reported as
     * {@code baseTheme.…}), the realm layer, then each organization layer. A font family that the realm's file theme
     * also provides keeps resolving, so deleting its last uploaded file does not break a typography reference.
     */
    public List<String> references(final String realmId, final ThemeAssetMetadata asset) {
        final boolean lastOfFamily = asset.kind() == ThemeAssetKind.FONT
                && servedFonts(realmId).stream().noneMatch(m -> !m.id().equals(asset.id())
                        && m.name().equals(asset.name()));
        final List<String> out = new ArrayList<>();
        for (final Theme base : themes.baseLayers(realmId)) {
            collect(base, "baseTheme.", realmId, asset, lastOfFamily, out);
        }
        collect(themes.realmTheme(realmId), "theme.", realmId, asset, lastOfFamily, out);
        themes.organizationThemes(realmId).forEach((orgId, theme) ->
                collect(theme, "organizations." + orgId + ".theme.", realmId, asset, lastOfFamily, out));
        return out;
    }

    private static void collect(final Theme theme, final String prefix, final String realmId,
                                final ThemeAssetMetadata asset, final boolean lastOfFamily, final List<String> out) {
        if (theme == null) {
            return;
        }
        final ThemeTypography t = theme.typography();
        if (lastOfFamily && t != null) {
            if (asset.name().equals(t.fontSans())) {
                out.add(prefix + "typography.fontSans");
            }
            if (asset.name().equals(t.fontDisplay())) {
                out.add(prefix + "typography.fontDisplay");
            }
        }
        final ThemeAssets a = theme.assets();
        if (a != null) {
            addIfRefers(a.logoUrl(), prefix + "assets.logoUrl", realmId, asset, out);
            addIfRefers(a.logoDarkUrl(), prefix + "assets.logoDarkUrl", realmId, asset, out);
            addIfRefers(a.faviconUrl(), prefix + "assets.faviconUrl", realmId, asset, out);
            addIfRefers(a.brandImageUrl(), prefix + "assets.brandImageUrl", realmId, asset, out);
        }
        if (theme.customCss() != null && theme.customCss().contains("/theme/assets/" + asset.id() + ".")) {
            out.add(prefix + "customCss");
        }
    }

    private static void addIfRefers(final String url, final String field, final String realmId,
                                    final ThemeAssetMetadata asset, final List<String> out) {
        ThemeUrls.parseAsset(url)
                .filter(ref -> ref.realmId().equals(realmId) && ref.assetId().equals(asset.id()))
                .ifPresent(ref -> out.add(field));
    }

    private void invalidateAfterCommit(final String realmId) {
        // Uploads can make stored custom CSS valid again and deletions can invalidate it: drop the cached effective
        // themes, once the change is visible to the next read.
        if (TransactionSynchronizationManager.isSynchronizationActive()) {
            TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization() {
                @Override
                public void afterCommit() {
                    themes.invalidate(realmId);
                }
            });
        } else {
            themes.invalidate(realmId);
        }
    }

    static String sha256(final byte[] bytes) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
        } catch (final NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
