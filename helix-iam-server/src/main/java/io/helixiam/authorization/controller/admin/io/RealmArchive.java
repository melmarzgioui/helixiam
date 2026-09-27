/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.controller.admin.io;

import io.helixiam.authorization.theme.Theme;
import io.helixiam.authorization.theme.ThemeAssets;
import io.helixiam.authorization.theme.ThemeUrls;
import io.helixiam.authorization.theme.asset.ThemeAssetRules;

import java.io.ByteArrayOutputStream;
import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UncheckedIOException;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.ZipEntry;
import java.util.zip.ZipException;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;

/**
 * The optional realm archive (spec §7: "asset bytes go in an optional archive export"): a zip holding
 * <ul>
 *   <li>{@value #DOCUMENT}: the realm export document, exactly as {@code GET /export} returns it;</li>
 *   <li>{@value #MANIFEST}: one entry per uploaded asset (id, kind, name, ext, weight, style, sha256, size);</li>
 *   <li>{@code theme-assets/{id}.{ext}}: the asset bytes.</li>
 * </ul>
 * Reading is defensive: only those names are accepted (no paths, so no zip-slip even though nothing is ever written
 * to disk), each name at most once, at most {@link Limits#maxEntries} entries, and every entry is inflated through
 * a counter that stops at its own cap and at the total uncompressed cap (zip bombs), with the compressed input
 * capped as well. Sizes declared in the zip headers are never trusted.
 */
public final class RealmArchive {

    /** The realm export document. */
    public static final String DOCUMENT = "realm-export.json";
    /** The asset manifest. */
    public static final String MANIFEST = "theme-assets/manifest.json";
    /** Folder of the asset files. */
    public static final String ASSET_DIR = "theme-assets/";

    private static final Pattern ASSET_ENTRY = Pattern.compile("theme-assets/([A-Za-z0-9_-]{1,64}\\.(?:woff2|svg|png|webp))");
    private static final Pattern ASSET_URL =
            Pattern.compile("/realms/[A-Za-z0-9._-]+/theme/assets/([A-Za-z0-9_-]{1,64})\\.([a-z0-9]{2,5})");

    private RealmArchive() {
    }

    /**
     * Caps applied while reading.
     *
     * @param maxEntries         entries in the zip (directories included)
     * @param maxAssetBytes      uncompressed bytes of one asset file (and of the manifest)
     * @param maxDocumentBytes   uncompressed bytes of the document
     * @param maxTotalBytes      uncompressed bytes of all entries together
     * @param maxCompressedBytes bytes of the zip itself
     */
    public record Limits(int maxEntries, int maxAssetBytes, int maxDocumentBytes, long maxTotalBytes,
                         long maxCompressedBytes) {

        /**
         * 8 fonts + 32 images + document + manifest fit with room to spare; an asset file is at most the largest
         * upload (512 KB); the document at most 16 MB; everything at most 40 MB uncompressed and 40 MB compressed.
         */
        public static final Limits DEFAULT = new Limits(64, ThemeAssetRules.MAX_RASTER_BYTES, 16 * 1024 * 1024,
                40L * 1024 * 1024, 40L * 1024 * 1024);
    }

    /** What an archive holds: the document, the manifest (empty when absent) and asset files by file name. */
    public record Contents(byte[] document, byte[] manifest, Map<String, byte[]> assets) {
    }

    /** Writes an archive. {@code assets} maps {@code {id}.{ext}} to the bytes. */
    public static void write(final OutputStream out, final byte[] document, final byte[] manifest,
                             final Map<String, byte[]> assets) throws IOException {
        final ZipOutputStream zip = new ZipOutputStream(out);
        entry(zip, DOCUMENT, document);
        entry(zip, MANIFEST, manifest);
        for (final Map.Entry<String, byte[]> a : assets.entrySet()) {
            entry(zip, ASSET_DIR + a.getKey(), a.getValue());
        }
        zip.finish();
    }

    private static void entry(final ZipOutputStream zip, final String name, final byte[] bytes) throws IOException {
        zip.putNextEntry(new ZipEntry(name));
        zip.write(bytes);
        zip.closeEntry();
    }

    /**
     * Reads an archive within {@code limits}.
     *
     * @throws RealmArchiveException when it is not a zip, holds an unexpected or duplicate entry, exceeds a cap, or
     *                               lacks the document
     */
    public static Contents read(final InputStream in, final Limits limits) {
        byte[] document = null;
        byte[] manifest = new byte[0];
        final Map<String, byte[]> assets = new LinkedHashMap<>();
        final Set<String> seen = new HashSet<>();
        final long[] total = {0};
        int entries = 0;
        try (ZipInputStream zip = new ZipInputStream(new CappedInputStream(in, limits.maxCompressedBytes()))) {
            ZipEntry e;
            while ((e = zip.getNextEntry()) != null) {
                if (++entries > limits.maxEntries()) {
                    throw new RealmArchiveException("The archive has more than " + limits.maxEntries() + " entries.");
                }
                final String name = e.getName();
                if (!seen.add(name)) {
                    throw new RealmArchiveException("The archive holds the entry " + safe(name) + " more than once.");
                }
                if (ASSET_DIR.equals(name) && e.isDirectory()) {
                    continue;
                }
                if (DOCUMENT.equals(name)) {
                    document = readCapped(zip, limits.maxDocumentBytes(), total, limits.maxTotalBytes(), name);
                } else if (MANIFEST.equals(name)) {
                    manifest = readCapped(zip, limits.maxAssetBytes(), total, limits.maxTotalBytes(), name);
                } else {
                    final Matcher m = ASSET_ENTRY.matcher(name);
                    if (e.isDirectory() || !m.matches()) {
                        throw new RealmArchiveException("Unexpected archive entry " + safe(name) + "; only " + DOCUMENT
                                + ", " + MANIFEST + " and theme-assets/{id}.{woff2|svg|png|webp} are allowed.");
                    }
                    assets.put(m.group(1), readCapped(zip, limits.maxAssetBytes(), total, limits.maxTotalBytes(), name));
                }
            }
        } catch (final ZipException ex) {
            throw new RealmArchiveException("The archive is not a valid zip file.");
        } catch (final IOException ex) {
            throw new UncheckedIOException(ex);
        }
        if (document == null) {
            throw new RealmArchiveException("The archive has no " + DOCUMENT + " entry (or is not a zip file).");
        }
        return new Contents(document, manifest, assets);
    }

    private static byte[] readCapped(final InputStream in, final int max, final long[] total, final long maxTotal,
                                     final String name) throws IOException {
        final ByteArrayOutputStream out = new ByteArrayOutputStream();
        final byte[] buf = new byte[8192];
        int n;
        while ((n = in.read(buf)) > 0) {
            total[0] += n;
            if (out.size() + n > max) {
                throw new RealmArchiveException("The archive entry " + safe(name) + " is too large (at most " + max
                        + " bytes).");
            }
            if (total[0] > maxTotal) {
                throw new RealmArchiveException("The archive is too large once uncompressed (at most " + maxTotal
                        + " bytes).");
            }
            out.write(buf, 0, n);
        }
        return out.toByteArray();
    }

    /**
     * Points every own-asset reference of {@code theme} whose id is in {@code ids} (old id → new id) at the new
     * asset in {@code realmId}: the four asset URLs and the {@code url()}s of the custom CSS. References to ids not
     * in the map are left as they are, so validation refuses them. Font fields refer by name and need no change.
     */
    public static Theme rewrite(final Theme theme, final String realmId, final Map<String, String> ids) {
        if (theme == null || ids.isEmpty()) {
            return theme;
        }
        Theme out = theme;
        final ThemeAssets a = theme.assets();
        if (a != null) {
            out = out.withAssets(new ThemeAssets(url(a.logoUrl(), realmId, ids), url(a.logoDarkUrl(), realmId, ids),
                    url(a.faviconUrl(), realmId, ids), url(a.brandImageUrl(), realmId, ids)));
        }
        if (theme.customCss() != null) {
            final Matcher m = ASSET_URL.matcher(theme.customCss());
            final StringBuilder css = new StringBuilder();
            while (m.find()) {
                final String newId = ids.get(m.group(1));
                m.appendReplacement(css, Matcher.quoteReplacement(newId == null ? m.group()
                        : ThemeUrls.assetPath(realmId, newId, m.group(2))));
            }
            m.appendTail(css);
            out = out.withCustomCss(css.toString());
        }
        return out;
    }

    private static String url(final String url, final String realmId, final Map<String, String> ids) {
        return ThemeUrls.parseAsset(url)
                .filter(ref -> ids.containsKey(ref.assetId()))
                .map(ref -> ThemeUrls.assetPath(realmId, ids.get(ref.assetId()), ref.extension()))
                .orElse(url);
    }

    private static String safe(final String name) {
        final String cleaned = name == null ? "" : name.replaceAll("[^A-Za-z0-9 ._/-]", "?");
        return "\"" + (cleaned.length() > 80 ? cleaned.substring(0, 80) + "…" : cleaned) + "\"";
    }

    /** Stops reading the compressed input after {@code max} bytes. */
    private static final class CappedInputStream extends FilterInputStream {
        private final long max;
        private long count;

        CappedInputStream(final InputStream in, final long max) {
            super(in);
            this.max = max;
        }

        @Override
        public int read() throws IOException {
            final int b = super.read();
            if (b >= 0) {
                count(1);
            }
            return b;
        }

        @Override
        public int read(final byte[] b, final int off, final int len) throws IOException {
            final int n = super.read(b, off, len);
            if (n > 0) {
                count(n);
            }
            return n;
        }

        private void count(final int n) {
            count += n;
            if (count > max) {
                throw new RealmArchiveException("The archive is too large (at most " + max + " bytes).");
            }
        }
    }
}
