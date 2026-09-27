/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.controller.admin.io;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.helixiam.authorization.security.audit.AuditContext;
import io.helixiam.authorization.security.audit.AuditEvent;
import io.helixiam.authorization.security.audit.AuditLog;
import io.helixiam.authorization.theme.ThemeService;
import io.helixiam.authorization.theme.ThemeValidationException;
import io.helixiam.authorization.theme.asset.ThemeAssetInUseException;
import io.helixiam.authorization.theme.asset.ThemeAssetKind;
import io.helixiam.authorization.theme.asset.ThemeAssetMetadata;
import io.helixiam.authorization.theme.asset.ThemeAssetService;
import io.helixiam.common.log.LogSafe;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionTemplate;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * The optional realm archive (spec §7; review I2): the export document plus the bytes of the realm's uploaded
 * theme fonts and images, so a branded realm survives export → import into another realm or installation.
 *
 * <p><b>Import</b> runs in this order and stops at the first problem:
 * <ol>
 *   <li>read the zip defensively ({@link RealmArchive#read}: names, duplicates, entry count, size caps);</li>
 *   <li>check the manifest against the files one to one, and each file's SHA-256 against the manifest (400);</li>
 *   <li>re-upload every asset through {@link ThemeAssetService#upload} — the same rules and per-realm limits as
 *       {@code POST /theme/assets} — in one transaction, so a refused asset rolls back the others (422, and the
 *       document is not imported). An identical asset already in the target realm is reused, so importing the same
 *       archive twice works;</li>
 *   <li>rewrite asset URLs in the realm and organization themes (including custom CSS) to the new ids;</li>
 *   <li>import the document as {@code POST /import} does, where the theme is validated as usual.</li>
 * </ol>
 */
@Service
public class RealmArchiveService {

    /** The result slice of the asset stage. */
    public static final String SLICE_THEME_ASSETS = "themeAssets";

    private static final org.apache.logging.log4j.Logger LOG =
            org.apache.logging.log4j.LogManager.getLogger(RealmArchiveService.class);

    private final RealmExportService exportService;
    private final RealmImportService importService;
    private final ThemeAssetService assets;
    private final ObjectMapper json;
    private final TransactionTemplate tx;
    private final ThemeService themes;
    private final AuditLog auditLog;

    public RealmArchiveService(final RealmExportService exportService, final RealmImportService importService,
                               final ThemeAssetService assets, final ObjectMapper json, final TransactionTemplate tx,
                               final ThemeService themes, final AuditLog auditLog) {
        this.exportService = exportService;
        this.importService = importService;
        this.assets = assets;
        this.json = json;
        this.tx = tx;
        this.themes = themes;
        this.auditLog = auditLog;
    }

    /** One manifest entry. */
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record ManifestEntry(String id, String kind, String name, String ext, String weight, String style,
                                String sha256, Integer size) {
    }

    /** The realm's export document and asset bytes as a zip. */
    public byte[] export(final String realmId) {
        final RealmExportDocument doc = exportService.export(realmId);
        final List<ManifestEntry> manifest = new ArrayList<>();
        final Map<String, byte[]> files = new LinkedHashMap<>();
        for (final ThemeAssetMetadata m : assets.list(realmId)) {
            final Optional<ThemeAssetService.StoredAsset> content = assets.content(realmId, m.id());
            if (content.isEmpty()) {
                continue; // deleted meanwhile
            }
            manifest.add(new ManifestEntry(m.id(), m.kind().key(), m.name(), m.ext(), m.weight(), m.style(), m.sha256(),
                    m.size()));
            files.put(m.id() + "." + m.ext(), content.get().bytes());
        }
        try {
            final ByteArrayOutputStream out = new ByteArrayOutputStream();
            RealmArchive.write(out, json.writeValueAsBytes(doc), json.writeValueAsBytes(manifest), files);
            return out.toByteArray();
        } catch (final IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    /** What the asset stage did, so it can be undone (N3) and audited (N4). */
    private record AssetStage(Map<String, String> ids, List<ThemeAssetMetadata> created, List<Replaced> replaced) {
    }

    /** A font face replaced under {@code onConflict=overwrite}. */
    private record Replaced(ThemeAssetMetadata original, byte[] originalBytes, ThemeAssetMetadata replacement) {
    }

    /**
     * Imports an archive into {@code realmId}.
     *
     * @param sourceIp client address for the per-asset audit events
     * @throws RealmArchiveException     when the archive is malformed or inconsistent (nothing is imported)
     * @throws ThemeValidationException  when the document's theme fails strict parsing (nothing is imported)
     */
    public RealmImportResult importArchive(final String realmId, final InputStream in, final ImportOptions options,
                                           final String sourceIp) {
        final ImportOptions opts = options == null ? ImportOptions.OVERWRITE : options;
        final RealmArchive.Contents contents = RealmArchive.read(in, RealmArchive.Limits.DEFAULT);
        final RealmExportDocument doc = parse(contents.document(), new TypeReference<RealmExportDocument>() { },
                RealmArchive.DOCUMENT);
        final List<ManifestEntry> manifest = contents.manifest().length == 0 ? List.of()
                : parse(contents.manifest(), new TypeReference<List<ManifestEntry>>() { }, RealmArchive.MANIFEST);
        checkManifest(manifest, contents.assets());

        final RealmImportResult.Builder result = new RealmImportResult.Builder(realmId);
        // Review R-I2: the realm slice first — it creates a realm that does not exist yet, and assets need its row.
        if (!importService.importRealmStage(realmId, doc, opts, result)) {
            return result.build();
        }
        if (!manifest.isEmpty() && !themes.realmExists(realmId)) {
            throw new RealmArchiveException("The realm does not exist and the archive has no realm settings to create it.");
        }
        final AssetStage stage;
        try {
            stage = tx.execute(s -> uploadAll(realmId, manifest, contents.assets(), opts, result));
        } catch (final ThemeValidationException | ThemeAssetInUseException e) {
            final String reason = e instanceof ThemeValidationException tve
                    ? String.join("; ", tve.fieldErrors().entrySet().stream()
                            .map(en -> en.getKey() + ": " + en.getValue()).toList())
                    : e.getMessage();
            result.failed(SLICE_THEME_ASSETS, reason);
            LOG.warn("Helix realm archive import [{}]: an asset was refused, no asset and no other slice was imported: {}",
                    LogSafe.sanitize(realmId), LogSafe.sanitize(reason));
            return result.build();
        }
        final Map<String, String> ids = stage.ids();
        final RealmExportDocument rewritten = doc.withThemes(RealmArchive.rewrite(doc.theme(), realmId, ids),
                doc.organizationThemes() == null ? null : doc.organizationThemes().stream()
                        .map(o -> o == null ? null : new RealmExportDocument.OrganizationThemeExport(o.organization(),
                                RealmArchive.rewrite(o.theme(), realmId, ids)))
                        .toList());
        final RealmImportResult out = importService.importRest(realmId, rewritten, opts, result);
        final AssetStage kept = out.hasFailures() ? compensate(realmId, stage) : stage;
        audit(realmId, kept, sourceIp);
        return out;
    }

    /**
     * Review N3: the document stage failed after the asset stage committed. Undo what this import did to assets
     * unless a theme stored by this same import now references it: created assets are removed, replaced font faces
     * are put back. Returns what was kept.
     */
    private AssetStage compensate(final String realmId, final AssetStage stage) {
        final List<ThemeAssetMetadata> keptCreated = new ArrayList<>();
        for (final ThemeAssetMetadata m : stage.created()) {
            if (!assets.removeIfUnreferenced(realmId, m.id())) {
                keptCreated.add(m);
            }
        }
        final List<Replaced> keptReplaced = new ArrayList<>();
        // Reverse order, so a chain of replacements unwinds back to the original (final check F-M1).
        for (final Replaced r : stage.replaced().reversed()) {
            final boolean referencedByUrl = assets.references(realmId, r.replacement()).stream()
                    .anyMatch(f -> !f.endsWith("typography.fontSans") && !f.endsWith("typography.fontDisplay"));
            if (referencedByUrl) {
                keptReplaced.add(r);
            } else {
                assets.restore(r.replacement(), r.original(), r.originalBytes());
            }
        }
        LOG.warn("Helix realm archive import [{}]: the document stage failed; {} new asset(s) removed, {} replaced "
                        + "font face(s) restored", LogSafe.sanitize(realmId),
                stage.created().size() - keptCreated.size(), stage.replaced().size() - keptReplaced.size());
        return new AssetStage(stage.ids(), keptCreated, keptReplaced);
    }

    /** Review N4: one audit event per asset this import stored (metadata only), besides the import event itself. */
    private void audit(final String realmId, final AssetStage stage, final String sourceIp) {
        if (auditLog == null) {
            return;
        }
        for (final Replaced r : stage.replaced()) {
            emit("THEME_ASSET_DELETE", realmId, r.original(), sourceIp);
            emit("THEME_ASSET_UPLOAD", realmId, r.replacement(), sourceIp);
        }
        for (final ThemeAssetMetadata m : stage.created()) {
            emit("THEME_ASSET_UPLOAD", realmId, m, sourceIp);
        }
    }

    private void emit(final String type, final String realmId, final ThemeAssetMetadata m, final String sourceIp) {
        final Map<String, String> detail = new LinkedHashMap<>();
        detail.put("assetId", m.id());
        detail.put("kind", m.kind().key());
        detail.put("name", m.name());
        detail.put("ext", m.ext());
        detail.put("size", Integer.toString(m.size()));
        detail.put("sha256", m.sha256());
        detail.put("source", "import");
        auditLog.emit(AuditEvent.admin(AuditContext.nowIso(), type, realmId, AuditContext.adminActor(), sourceIp,
                "theme-asset", m.id(), "SUCCESS", detail));
    }

    /**
     * Review N2: {@code onConflict} applies to assets as to the other slices. An asset "exists" when the target realm
     * has the same font face (family case-insensitively, weight, style) or, for an image, identical content.
     * <ul>
     *   <li>{@code overwrite}: an identical asset is reused; a font face with other bytes is replaced (the family keeps
     *       resolving; refused when custom CSS references the old file);</li>
     *   <li>{@code skip}: the existing asset is kept and used;</li>
     *   <li>{@code fail}: as skip, and each existing asset is reported as a conflict {@code themeAssets:font Name 400
     *       normal} / {@code themeAssets:image name.ext}.</li>
     * </ul>
     * New assets are uploaded in every mode.
     */
    private AssetStage uploadAll(final String realmId, final List<ManifestEntry> manifest,
                                 final Map<String, byte[]> files, final ImportOptions opts,
                                 final RealmImportResult.Builder result) {
        final Map<String, String> ids = new LinkedHashMap<>();
        final List<ThemeAssetMetadata> created = new ArrayList<>();
        final List<Replaced> replaced = new ArrayList<>();
        final List<ThemeAssetMetadata> existing = new ArrayList<>(assets.list(realmId));
        for (final ManifestEntry e : manifest) {
            final byte[] bytes = files.get(e.id() + "." + e.ext());
            final boolean font = ThemeAssetKind.FONT.key().equals(e.kind());
            final String weight = font ? (e.weight() == null ? "400" : e.weight()) : null;
            final String style = font ? (e.style() == null ? "normal" : e.style()) : null;
            final Optional<ThemeAssetMetadata> match = existing.stream()
                    .filter(m -> font ? m.kind() == ThemeAssetKind.FONT && m.name().equalsIgnoreCase(e.name())
                            && m.weight().equals(weight) && m.style().equals(style)
                            : m.kind() == ThemeAssetKind.IMAGE && identical(m, e))
                    .findFirst();
            if (match.isEmpty()) {
                final ThemeAssetMetadata uploaded = assets.upload(realmId, e.id() + "." + e.ext(), bytes, e.name(),
                        weight, style);
                existing.add(uploaded);
                created.add(uploaded);
                ids.put(e.id(), uploaded.id());
                result.created(SLICE_THEME_ASSETS);
                continue;
            }
            final ThemeAssetMetadata current = match.get();
            switch (opts.onConflict()) {
                case SKIP -> result.skipped(SLICE_THEME_ASSETS);
                case FAIL -> {
                    result.conflict(SLICE_THEME_ASSETS, font ? "font " + current.name() + " " + weight + " " + style
                            : "image " + current.name() + "." + current.ext());
                    result.skipped(SLICE_THEME_ASSETS);
                }
                default -> {
                    if (!font || identical(current, e)) {
                        result.updated(SLICE_THEME_ASSETS);
                    } else {
                        final byte[] originalBytes = assets.content(realmId, current.id())
                                .map(ThemeAssetService.StoredAsset::bytes).orElseThrow();
                        final ThemeAssetMetadata replacement = assets.replaceFont(realmId, current.id(),
                                e.id() + "." + e.ext(), bytes, e.name(), weight, style);
                        existing.remove(current);
                        existing.add(replacement);
                        replaced.add(new Replaced(current, originalBytes, replacement));
                        ids.put(e.id(), replacement.id());
                        result.updated(SLICE_THEME_ASSETS);
                        continue;
                    }
                }
            }
            ids.put(e.id(), current.id());
        }
        return new AssetStage(ids, created, replaced);
    }

    private static boolean identical(final ThemeAssetMetadata m, final ManifestEntry e) {
        return m.sha256().equals(e.sha256()) && m.ext().equals(e.ext()) && m.kind().key().equals(e.kind())
                && (m.kind() != ThemeAssetKind.FONT || (m.name().equals(e.name())
                && java.util.Objects.equals(m.weight(), e.weight() == null ? "400" : e.weight())
                && java.util.Objects.equals(m.style(), e.style() == null ? "normal" : e.style())));
    }

    /** One manifest entry per file and one file per entry; ids, kinds and hashes consistent. */
    private static void checkManifest(final List<ManifestEntry> manifest, final Map<String, byte[]> files) {
        final Set<String> named = new HashSet<>();
        final Set<String> faces = new HashSet<>();
        for (final ManifestEntry e : manifest) {
            if (e == null || e.id() == null || e.ext() == null || e.sha256() == null || e.kind() == null
                    || !e.id().matches("[A-Za-z0-9_-]{1,64}") || !e.ext().matches("woff2|svg|png|webp")) {
                throw new RealmArchiveException("The asset manifest has an incomplete or invalid entry.");
            }
            final boolean font = "woff2".equals(e.ext());
            if (!(font ? "font" : "image").equals(e.kind())) {
                throw new RealmArchiveException("The asset manifest entry " + e.id() + " has the wrong kind.");
            }
            if (font) {
                // Final check F-M1: one face per (family case-insensitively, weight, style), or overwrite would replace
                // a face it created itself and the undo could not restore it.
                final String face = String.valueOf(e.name()).toLowerCase(java.util.Locale.ROOT) + "|"
                        + (e.weight() == null ? "400" : e.weight()) + "|" + (e.style() == null ? "normal" : e.style());
                if (!faces.add(face)) {
                    throw new RealmArchiveException("The asset manifest lists the font face " + e.name() + " "
                            + (e.weight() == null ? "400" : e.weight()) + " " + (e.style() == null ? "normal" : e.style())
                            + " more than once.");
                }
            }
            final String file = e.id() + "." + e.ext();
            if (!named.add(file)) {
                throw new RealmArchiveException("The asset manifest lists " + file + " more than once.");
            }
            final byte[] bytes = files.get(file);
            if (bytes == null) {
                throw new RealmArchiveException("The archive has no file for manifest entry " + file + ".");
            }
            if (!sha256(bytes).equalsIgnoreCase(e.sha256())) {
                throw new RealmArchiveException("The sha256 of " + file + " does not match the manifest.");
            }
        }
        for (final String file : files.keySet()) {
            if (!named.contains(file)) {
                throw new RealmArchiveException("The archive file theme-assets/" + file + " is not in the manifest.");
            }
        }
    }

    private <T> T parse(final byte[] bytes, final TypeReference<T> type, final String entry) {
        try {
            return json.readValue(bytes, type);
        } catch (final JsonProcessingException e) {
            Throwable c = e;
            while (c != null) {
                if (c instanceof ThemeValidationException tve) {
                    throw tve;
                }
                c = c.getCause();
            }
            throw new RealmArchiveException("The archive entry " + entry + " is not valid JSON for its format.");
        } catch (final IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    private static String sha256(final byte[] bytes) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
        } catch (final NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
