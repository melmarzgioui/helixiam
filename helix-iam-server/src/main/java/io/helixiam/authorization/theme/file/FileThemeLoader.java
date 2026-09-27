/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.theme.file;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.json.JsonMapper;
import io.helixiam.authorization.theme.Theme;
import io.helixiam.authorization.theme.ThemeAssetCatalog;
import io.helixiam.authorization.theme.ThemeAssets;
import io.helixiam.authorization.theme.ThemeDefaults;
import io.helixiam.authorization.theme.ThemeJson;
import io.helixiam.authorization.theme.ThemeNormalizer;
import io.helixiam.authorization.theme.ThemeUrls;
import io.helixiam.authorization.theme.ThemeValidationException;
import io.helixiam.authorization.theme.ThemeValidator;
import io.helixiam.authorization.theme.asset.ThemeAssetKind;
import io.helixiam.authorization.theme.asset.ThemeAssetRules;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

/**
 * Reads and validates one file theme directory (spec §5). Pure apart from reading files; never writes anything.
 *
 * <pre>
 * {name}/theme.json      the theme, same schema as PUT /admin/realms/{r}/theme (parsed strictly)
 * {name}/fonts.json      optional: [{"file": "PublicSans.woff2", "family": "Public Sans", "weight": "100 900", "style": "normal"}]
 * {name}/assets/*        fonts (.woff2) and images (.svg, .png, .webp)
 * </pre>
 *
 * In {@code theme.json} an asset field or a custom-CSS {@code url()} refers to a file as {@code assets/<file>}.
 * Every file goes through {@link ThemeAssetRules#check} (type confirmed by content, size limits, the rejecting SVG
 * validator, font names) and the per-realm count limits; the theme itself goes through {@link ThemeNormalizer} and
 * {@link ThemeValidator} exactly like an admin-API theme (with the theme's own files as the only uploaded assets).
 * A theme is also refused when a file is not a regular file inside the theme directory (symbolic links are followed
 * only while they stay inside the themes root, which is how a Kubernetes ConfigMap mount lays files out).
 */
public final class FileThemeLoader {

    /** Theme directory names: what a realm selects. */
    public static final Pattern NAME = Pattern.compile("[A-Za-z0-9][A-Za-z0-9._-]{0,63}");
    /** Asset file names that {@code assets/<file>} may refer to. */
    static final Pattern FILE = Pattern.compile("[A-Za-z0-9][A-Za-z0-9._-]{0,99}");
    static final int MAX_JSON_BYTES = 256 * 1024;
    private static final int MAX_ASSET_BYTES = Math.max(ThemeAssetRules.MAX_FONT_BYTES, ThemeAssetRules.MAX_RASTER_BYTES);
    private static final String ASSET_REF = "assets/";
    private static final Pattern CSS_ASSET_URL = Pattern.compile("url\\(\\s*(['\"]?)assets/([^'\")\\s]*)\\1\\s*\\)");
    private static final ObjectMapper JSON = JsonMapper.builder()
            .enable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES).build();

    private FileThemeLoader() {
    }

    /** The outcome for one theme: the loaded theme, or the problems (field or file → message) that refused it. */
    public record Result(String name, FileTheme theme, Map<String, String> problems) {

        public boolean valid() {
            return theme != null;
        }

        static Result refused(final String name, final Map<String, String> problems) {
            return new Result(name, null, Map.copyOf(problems));
        }
    }

    /** One {@code fonts.json} entry. */
    record FontEntry(String file, String family, String weight, String style) {
    }

    /**
     * Loads {@code root/name}. {@code operatorOrigins} is {@code helix.theme.allowed-image-origins}, which also
     * bounds a file theme's custom-CSS {@code url()}s.
     */
    public static Result load(final Path root, final String name, final Collection<String> operatorOrigins) {
        final Map<String, String> problems = new TreeMap<>();
        if (name == null || !NAME.matcher(name).matches()) {
            problems.put("name", "A theme directory name must be 1-64 letters, digits, '.', '_' or '-', starting with a"
                    + " letter or digit.");
            return Result.refused(name, problems);
        }
        final Path realRoot;
        final Path dir;
        try {
            realRoot = root.toRealPath();
            dir = inside(realRoot, root.resolve(name));
        } catch (final IOException | IllegalArgumentException e) {
            problems.put("directory", "The theme directory cannot be read: " + message(e));
            return Result.refused(name, problems);
        }
        if (!Files.isDirectory(dir)) {
            problems.put("directory", "Not a directory.");
            return Result.refused(name, problems);
        }

        final List<FontEntry> fonts = readFonts(realRoot, dir, problems);
        final Map<String, FileTheme.FileAsset> byFile = readAssets(realRoot, name, dir, fonts, problems);
        final JsonNode json = readJson(realRoot, dir.resolve("theme.json"), "theme.json", problems);
        if (json == null) {
            return Result.refused(name, problems);
        }
        // Every problem is reported at once (files and theme.json), so an operator fixes a theme in one pass.
        Theme theme;
        try {
            theme = ThemeJson.readStrict(json);
        } catch (final ThemeValidationException e) {
            e.fieldErrors().forEach((k, v) -> problems.put("theme.json: " + k, v));
            return Result.refused(name, problems);
        }
        theme = ThemeNormalizer.normalize(resolveReferences(theme, byFile, problems));
        final Map<String, FileTheme.FileAsset> byId = new LinkedHashMap<>();
        byFile.values().forEach(a -> byId.put(a.id(), a));
        final ThemeValidator validator = new ThemeValidator(catalog(byId), operatorOrigins);
        // putIfAbsent: an unresolved assets/ reference keeps its clearer message.
        validator.validate(FileTheme.PLACEHOLDER_REALM, ThemeValidator.Scope.REALM, theme, ThemeDefaults.THEME)
                .forEach((k, v) -> problems.putIfAbsent("theme.json: " + k, v));
        if (problems.isEmpty()) {
            return new Result(name, new FileTheme(name, theme, byId, fingerprint(json, byFile)), Map.of());
        }
        return Result.refused(name, problems);
    }

    /** The theme's own files as the catalog the validator checks fonts and asset URLs against. */
    static ThemeAssetCatalog catalog(final Map<String, FileTheme.FileAsset> byId) {
        return new ThemeAssetCatalog() {
            @Override
            public boolean hasFont(final String realmId, final String fontName) {
                return byId.values().stream().anyMatch(a -> a.kind() == ThemeAssetKind.FONT && a.name().equals(fontName));
            }

            @Override
            public boolean hasAsset(final String realmId, final String assetId, final String extension) {
                final FileTheme.FileAsset a = byId.get(assetId);
                return a != null && a.ext().equals(extension);
            }
        };
    }

    // ------------------------------------------------------------------ files

    private static List<FontEntry> readFonts(final Path realRoot, final Path dir, final Map<String, String> problems) {
        final Path file = dir.resolve("fonts.json");
        if (!Files.exists(file)) {
            return List.of();
        }
        final JsonNode node = readJson(realRoot, file, "fonts.json", problems);
        if (node == null) {
            return List.of();
        }
        if (!node.isArray()) {
            problems.put("fonts.json", "Must be a JSON array of {file, family, weight, style}.");
            return List.of();
        }
        final List<FontEntry> out = new ArrayList<>();
        for (int i = 0; i < node.size(); i++) {
            try {
                final FontEntry e = JSON.treeToValue(node.get(i), FontEntry.class);
                if (e == null || e.file() == null || e.family() == null) {
                    problems.put("fonts.json[" + i + "]", "Each entry needs file and family.");
                } else {
                    out.add(e);
                }
            } catch (final IOException | IllegalArgumentException e) {
                problems.put("fonts.json[" + i + "]", "Invalid entry (fields: file, family, weight, style).");
            }
        }
        return out;
    }

    private static Map<String, FileTheme.FileAsset> readAssets(final Path realRoot, final String themeName,
                                                               final Path dir, final List<FontEntry> fonts,
                                                               final Map<String, String> problems) {
        final Map<String, FileTheme.FileAsset> byFile = new TreeMap<>();
        final Path assets = dir.resolve("assets");
        if (!Files.exists(assets)) {
            fonts.forEach(f -> problems.put("fonts.json", "Font file assets/" + f.file() + " does not exist."));
            return byFile;
        }
        final Map<String, FontEntry> fontByFile = new LinkedHashMap<>();
        for (final FontEntry f : fonts) {
            if (fontByFile.put(f.file(), f) != null) {
                problems.put("fonts.json", "assets/" + f.file() + " is listed more than once.");
            }
        }
        final List<Path> entries;
        try (Stream<Path> s = Files.list(inside(realRoot, assets))) {
            entries = s.sorted().toList();
        } catch (final IOException | IllegalArgumentException e) {
            problems.put("assets", "The assets directory cannot be read: " + message(e));
            return byFile;
        }
        int fontCount = 0;
        int imageCount = 0;
        for (final Path entry : entries) {
            final String file = entry.getFileName().toString();
            if (file.startsWith(".")) {
                continue; // hidden files (editor or volume bookkeeping) are never assets
            }
            final String key = "assets/" + file;
            if (!FILE.matcher(file).matches()) {
                problems.put(key, "Asset file names must be 1-100 letters, digits, '.', '_' or '-'.");
                continue;
            }
            final byte[] bytes;
            try {
                final Path real = inside(realRoot, entry);
                if (!Files.isRegularFile(real)) {
                    problems.put(key, "Not a regular file.");
                    continue;
                }
                bytes = readCapped(real, MAX_ASSET_BYTES);
            } catch (final IOException | IllegalArgumentException e) {
                problems.put(key, message(e));
                continue;
            }
            if (bytes == null) {
                problems.put(key, "The file is larger than any theme asset may be.");
                continue;
            }
            final FontEntry font = fontByFile.remove(file);
            if (font == null && file.endsWith(".woff2")) {
                problems.put(key, "A font file must be listed in fonts.json with its family (and weight and style).");
                continue;
            }
            final ThemeAssetRules.Accepted accepted;
            try {
                accepted = ThemeAssetRules.check(file, bytes, font == null ? null : font.family(),
                        font == null ? null : font.weight(), font == null ? null : font.style());
            } catch (final ThemeValidationException e) {
                e.fieldErrors().forEach((k, v) -> problems.put(key + ("file".equals(k) ? "" : " (" + k + ")"), v));
                continue;
            }
            if (accepted.kind() == ThemeAssetKind.IMAGE && font != null) {
                problems.put("fonts.json", key + " is not a font file.");
                continue;
            }
            if (accepted.kind() == ThemeAssetKind.FONT ? ++fontCount > ThemeAssetRules.MAX_FONTS
                    : ++imageCount > ThemeAssetRules.MAX_IMAGES) {
                problems.put(key, "A theme may have at most " + ThemeAssetRules.MAX_FONTS + " fonts and "
                        + ThemeAssetRules.MAX_IMAGES + " images, like a realm.");
                continue;
            }
            final String sha = sha256(bytes);
            final String id = "ft-" + sha256((themeName + "\n" + file + "\n" + sha).getBytes(StandardCharsets.UTF_8))
                    .substring(0, 40);
            byFile.put(file, new FileTheme.FileAsset(id, file, accepted.kind(), accepted.name(), accepted.extension(),
                    accepted.contentType(), bytes, sha, accepted.weight(), accepted.style()));
        }
        fontByFile.keySet().forEach(f -> problems.put("fonts.json", "Font file assets/" + f + " does not exist."));
        return byFile;
    }

    private static JsonNode readJson(final Path realRoot, final Path file, final String label,
                                     final Map<String, String> problems) {
        try {
            final Path real = inside(realRoot, file);
            if (!Files.isRegularFile(real)) {
                problems.put(label, "Missing (or not a regular file).");
                return null;
            }
            final byte[] bytes = readCapped(real, MAX_JSON_BYTES);
            if (bytes == null) {
                problems.put(label, "Larger than " + (MAX_JSON_BYTES / 1024) + " KB.");
                return null;
            }
            return JSON.readTree(bytes);
        } catch (final java.nio.file.NoSuchFileException e) {
            problems.put(label, "Missing.");
        } catch (final IOException | IllegalArgumentException e) {
            problems.put(label, "Not valid JSON or not readable: " + message(e));
        }
        return null;
    }

    /**
     * The real path of {@code path}, which must stay inside {@code realRoot} (links are resolved first, so a link that
     * points out of the themes directory is refused).
     */
    static Path inside(final Path realRoot, final Path path) throws IOException {
        final Path real = path.toRealPath();
        if (!real.startsWith(realRoot)) {
            throw new IllegalArgumentException("It points outside the themes directory.");
        }
        return real;
    }

    /** The file's bytes, or null when it has more than {@code max} bytes (never reads more than max + 1). */
    private static byte[] readCapped(final Path file, final int max) throws IOException {
        try (InputStream in = Files.newInputStream(file)) {
            final byte[] bytes = in.readNBytes(max + 1);
            return bytes.length > max ? null : bytes;
        }
    }

    // ------------------------------------------------------------------ references

    private static Theme resolveReferences(final Theme theme, final Map<String, FileTheme.FileAsset> byFile,
                                           final Map<String, String> problems) {
        Theme t = theme;
        final ThemeAssets a = t.assets();
        if (a != null) {
            t = t.withAssets(new ThemeAssets(
                    ref(a.logoUrl(), "assets.logoUrl", byFile, problems),
                    ref(a.logoDarkUrl(), "assets.logoDarkUrl", byFile, problems),
                    ref(a.faviconUrl(), "assets.faviconUrl", byFile, problems),
                    ref(a.brandImageUrl(), "assets.brandImageUrl", byFile, problems)));
        }
        if (t.customCss() != null) {
            final Matcher m = CSS_ASSET_URL.matcher(t.customCss());
            final StringBuilder css = new StringBuilder();
            while (m.find()) {
                final FileTheme.FileAsset asset = byFile.get(m.group(2));
                final String replacement;
                if (asset == null) {
                    problems.put("theme.json: customCss", "url(assets/" + m.group(2) + ") names a file that is not in"
                            + " assets/ (or was refused).");
                    replacement = m.group();
                } else {
                    replacement = "url(" + m.group(1) + placeholderPath(asset) + m.group(1) + ")";
                }
                m.appendReplacement(css, Matcher.quoteReplacement(replacement));
            }
            m.appendTail(css);
            t = t.withCustomCss(css.toString());
        }
        return t;
    }

    private static String ref(final String value, final String field, final Map<String, FileTheme.FileAsset> byFile,
                              final Map<String, String> problems) {
        if (value == null || !value.startsWith(ASSET_REF)) {
            return value; // an https URL (validated like any theme) or unset
        }
        final FileTheme.FileAsset asset = byFile.get(value.substring(ASSET_REF.length()));
        if (asset == null) {
            problems.put("theme.json: " + field, value + " is not a file in assets/ (or was refused).");
            return value;
        }
        if (asset.kind() != ThemeAssetKind.IMAGE) {
            problems.put("theme.json: " + field, value + " is not an image.");
            return value;
        }
        return placeholderPath(asset);
    }

    private static String placeholderPath(final FileTheme.FileAsset asset) {
        return ThemeUrls.assetPath(FileTheme.PLACEHOLDER_REALM, asset.id(), asset.ext());
    }

    // ------------------------------------------------------------------ helpers

    private static String fingerprint(final JsonNode json, final Map<String, FileTheme.FileAsset> byFile) {
        final StringBuilder b = new StringBuilder(json.toString());
        byFile.forEach((file, a) -> b.append('\n').append(file).append('=').append(a.sha256()));
        return sha256(b.toString().getBytes(StandardCharsets.UTF_8));
    }

    static String sha256(final byte[] bytes) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
        } catch (final NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    /** A short reason without file-system paths (these messages reach realm admins through the admin API). */
    private static String message(final Exception e) {
        if (e instanceof java.nio.file.NoSuchFileException) {
            return "Missing.";
        }
        if (e instanceof java.nio.file.AccessDeniedException) {
            return "Not readable (permission denied).";
        }
        if (e instanceof com.fasterxml.jackson.core.JsonProcessingException j) {
            return j.getOriginalMessage();
        }
        if (e instanceof IllegalArgumentException) {
            return e.getMessage();
        }
        return "Cannot be read (" + e.getClass().getSimpleName() + ").";
    }

    /** The theme names under {@code root}: its sub-directories, minus hidden and Kubernetes bookkeeping entries. */
    public static List<String> names(final Path root) throws IOException {
        try (Stream<Path> s = Files.list(root)) {
            return s.filter(Files::isDirectory)
                    .map(p -> p.getFileName().toString())
                    .filter(n -> !n.startsWith("."))
                    .sorted()
                    .toList();
        }
    }
}
