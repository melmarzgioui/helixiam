/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.controller.admin.io;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.helixiam.authorization.theme.ThemeValidationException;
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

    public RealmArchiveService(final RealmExportService exportService, final RealmImportService importService,
                               final ThemeAssetService assets, final ObjectMapper json, final TransactionTemplate tx) {
        this.exportService = exportService;
        this.importService = importService;
        this.assets = assets;
        this.json = json;
        this.tx = tx;
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

    /**
     * Imports an archive into {@code realmId}.
     *
     * @throws RealmArchiveException     when the archive is malformed or inconsistent (nothing is imported)
     * @throws ThemeValidationException  when the document's theme fails strict parsing (nothing is imported)
     */
    public RealmImportResult importArchive(final String realmId, final InputStream in, final ImportOptions options) {
        final RealmArchive.Contents contents = RealmArchive.read(in, RealmArchive.Limits.DEFAULT);
        final RealmExportDocument doc = parse(contents.document(), new TypeReference<RealmExportDocument>() { },
                RealmArchive.DOCUMENT);
        final List<ManifestEntry> manifest = contents.manifest().length == 0 ? List.of()
                : parse(contents.manifest(), new TypeReference<List<ManifestEntry>>() { }, RealmArchive.MANIFEST);
        checkManifest(manifest, contents.assets());

        final RealmImportResult.Builder result = new RealmImportResult.Builder(realmId);
        final Map<String, String> ids;
        try {
            ids = tx.execute(s -> uploadAll(realmId, manifest, contents.assets(), result));
        } catch (final ThemeValidationException e) {
            final String reason = String.join("; ", e.fieldErrors().entrySet().stream()
                    .map(en -> en.getKey() + ": " + en.getValue()).toList());
            result.failed(SLICE_THEME_ASSETS, reason);
            LOG.warn("Helix realm archive import [{}]: an asset was refused, nothing was imported: {}",
                    LogSafe.sanitize(realmId), LogSafe.sanitize(reason));
            return result.build();
        }
        final RealmExportDocument rewritten = doc.withThemes(RealmArchive.rewrite(doc.theme(), realmId, ids),
                doc.organizationThemes() == null ? null : doc.organizationThemes().stream()
                        .map(o -> o == null ? null : new RealmExportDocument.OrganizationThemeExport(o.organization(),
                                RealmArchive.rewrite(o.theme(), realmId, ids)))
                        .toList());
        return importService.importInto(realmId, rewritten, options, result);
    }

    private Map<String, String> uploadAll(final String realmId, final List<ManifestEntry> manifest,
                                          final Map<String, byte[]> files, final RealmImportResult.Builder result) {
        final Map<String, String> ids = new LinkedHashMap<>();
        final List<ThemeAssetMetadata> existing = new ArrayList<>(assets.list(realmId));
        for (final ManifestEntry e : manifest) {
            final byte[] bytes = files.get(e.id() + "." + e.ext());
            final Optional<ThemeAssetMetadata> same = existing.stream().filter(m -> identical(m, e)).findFirst();
            if (same.isPresent()) {
                ids.put(e.id(), same.get().id());
                result.updated(SLICE_THEME_ASSETS);
                continue;
            }
            final boolean font = ThemeAssetKind.FONT.key().equals(e.kind());
            final ThemeAssetMetadata uploaded = assets.upload(realmId, e.id() + "." + e.ext(), bytes,
                    e.name(), font ? e.weight() : null, font ? e.style() : null);
            existing.add(uploaded);
            ids.put(e.id(), uploaded.id());
            result.created(SLICE_THEME_ASSETS);
        }
        return ids;
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
        for (final ManifestEntry e : manifest) {
            if (e == null || e.id() == null || e.ext() == null || e.sha256() == null || e.kind() == null
                    || !e.id().matches("[A-Za-z0-9_-]{1,64}") || !e.ext().matches("woff2|svg|png|webp")) {
                throw new RealmArchiveException("The asset manifest has an incomplete or invalid entry.");
            }
            final boolean font = "woff2".equals(e.ext());
            if (!(font ? "font" : "image").equals(e.kind())) {
                throw new RealmArchiveException("The asset manifest entry " + e.id() + " has the wrong kind.");
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
