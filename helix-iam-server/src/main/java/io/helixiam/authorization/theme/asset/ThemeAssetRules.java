/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.theme.asset;

import io.helixiam.authorization.theme.ThemeDefaults;
import io.helixiam.authorization.theme.ThemeValidationException;

import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Upload rules for theme assets (spec §3). The type is decided by the file name's extension and must be confirmed by
 * the content: {@code wOF2} for woff2, the PNG signature, {@code RIFF….WEBPVP8*} for WebP, and a full
 * {@link SvgValidator} pass for SVG. The declared multipart content type is never trusted.
 *
 * <table>
 *   <caption>Limits</caption>
 *   <tr><th>Type</th><th>Max size</th><th>Per realm</th></tr>
 *   <tr><td>woff2</td><td>500 KB</td><td>{@value #MAX_FONTS} fonts</td></tr>
 *   <tr><td>png, webp</td><td>512 KB</td><td rowspan="2">{@value #MAX_IMAGES} images</td></tr>
 *   <tr><td>svg</td><td>256 KB</td></tr>
 * </table>
 *
 * Names ({@code [A-Za-z0-9][A-Za-z0-9 ._-]{0,63}}, no leading or trailing space) end up quoted in the generated
 * {@code theme.css} as a {@code font-family}, so they can never contain a quote, a backslash, a brace, a
 * semicolon, a slash or a control character. A font name may not shadow a built-in stack.
 */
public final class ThemeAssetRules {

    /** Largest woff2 font, in bytes (500 KB). */
    public static final int MAX_FONT_BYTES = 500 * 1024;
    /** Largest PNG or WebP image, in bytes (512 KB). */
    public static final int MAX_RASTER_BYTES = 512 * 1024;
    /** Largest SVG image, in bytes (256 KB). */
    public static final int MAX_SVG_BYTES = 256 * 1024;
    /** Fonts per realm. */
    public static final int MAX_FONTS = 8;
    /** Images per realm. */
    public static final int MAX_IMAGES = 32;

    /** Accepted asset names (font family names end up in CSS: nothing that can break out of a quoted string). */
    public static final Pattern NAME = Pattern.compile("[A-Za-z0-9](?:[A-Za-z0-9 ._-]{0,62}[A-Za-z0-9._-])?");
    private static final Pattern WEIGHT = Pattern.compile("([1-9]00)(?: ([1-9]00))?");
    private static final Pattern EXTENSION = Pattern.compile("[A-Za-z0-9]{1,8}");

    private static final byte[] PNG = {(byte) 0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n'};

    private ThemeAssetRules() {
    }

    /** A checked upload. */
    public record Accepted(ThemeAssetKind kind, String extension, String contentType, String name, String weight,
                           String style) {
    }

    /** The content type served for an extension. */
    public static Optional<String> contentType(final String extension) {
        return Optional.ofNullable(switch (extension) {
            case "woff2" -> "font/woff2";
            case "svg" -> "image/svg+xml";
            case "png" -> "image/png";
            case "webp" -> "image/webp";
            default -> null;
        });
    }

    /**
     * Checks one upload. {@code name} is required for a font (its family name) and optional for an image (defaults
     * to the file name); {@code weight} ({@code 400}, or a variable range {@code 100 900}) and {@code style}
     * ({@code normal}|{@code italic}) apply to fonts only.
     *
     * @throws ThemeValidationException with errors under {@code file}, {@code name}, {@code weight}, {@code style}
     */
    public static Accepted check(final String filename, final byte[] bytes, final String name, final String weight,
                                 final String style) {
        final Map<String, String> errors = new LinkedHashMap<>();
        final String ext = extension(filename);
        final Optional<String> type = ext == null ? Optional.empty() : contentType(ext);
        if (type.isEmpty()) {
            errors.put("file", "The file name must end in .woff2 (fonts) or .svg, .png or .webp (images).");
            throw new ThemeValidationException(errors);
        }
        final ThemeAssetKind kind = "woff2".equals(ext) ? ThemeAssetKind.FONT : ThemeAssetKind.IMAGE;
        contentProblem(ext, bytes).ifPresent(p -> errors.put("file", p));

        String acceptedName = blankToNull(name);
        if (acceptedName == null && kind == ThemeAssetKind.IMAGE) {
            acceptedName = nameFromFile(filename);
        }
        if (acceptedName == null) {
            errors.put("name", "A font needs a name: the family name the theme uses in typography.fontSans or fontDisplay.");
        } else if (!NAME.matcher(acceptedName).matches()) {
            errors.put("name", "Use 1–64 letters, digits, spaces, dots, underscores or hyphens, starting with a letter "
                    + "or digit and not ending in a space.");
        } else if (kind == ThemeAssetKind.FONT && ThemeDefaults.BUILT_IN_FONTS.stream()
                .anyMatch(b -> b.equalsIgnoreCase(name))) {
            errors.put("name", "The name of a built-in font stack cannot be used for an uploaded font.");
        }

        String acceptedWeight = null;
        String acceptedStyle = null;
        if (kind == ThemeAssetKind.FONT) {
            acceptedWeight = blankToNull(weight) == null ? "400" : weight.trim();
            final Matcher w = WEIGHT.matcher(acceptedWeight);
            if (!w.matches() || (w.group(2) != null && Integer.parseInt(w.group(2)) <= Integer.parseInt(w.group(1)))) {
                errors.put("weight", "Use a weight from 100 to 900 in steps of 100, or a range such as \"100 900\" "
                        + "for a variable font.");
            }
            acceptedStyle = blankToNull(style) == null ? "normal" : style.trim();
            if (!"normal".equals(acceptedStyle) && !"italic".equals(acceptedStyle)) {
                errors.put("style", "Use normal or italic.");
            }
        } else {
            if (blankToNull(weight) != null) {
                errors.put("weight", "Only fonts have a weight.");
            }
            if (blankToNull(style) != null) {
                errors.put("style", "Only fonts have a style.");
            }
        }
        if (!errors.isEmpty()) {
            throw new ThemeValidationException(errors);
        }
        return new Accepted(kind, ext, type.get(), acceptedName, acceptedWeight, acceptedStyle);
    }

    /** Why {@code bytes} are not a valid file of type {@code ext}, or empty. */
    static Optional<String> contentProblem(final String ext, final byte[] bytes) {
        if (bytes == null || bytes.length == 0) {
            return Optional.of("The file is empty.");
        }
        return switch (ext) {
            case "woff2" -> {
                if (bytes.length > MAX_FONT_BYTES) {
                    yield Optional.of("A font may be at most 500 KB.");
                }
                yield isWoff2(bytes) ? Optional.empty()
                        : Optional.of("The file is not a woff2 font (it must start with the wOF2 signature).");
            }
            case "png" -> {
                if (bytes.length > MAX_RASTER_BYTES) {
                    yield Optional.of("A PNG image may be at most 512 KB.");
                }
                yield isPng(bytes) ? Optional.empty() : Optional.of("The file is not a PNG image.");
            }
            case "webp" -> {
                if (bytes.length > MAX_RASTER_BYTES) {
                    yield Optional.of("A WebP image may be at most 512 KB.");
                }
                yield isWebp(bytes) ? Optional.empty() : Optional.of("The file is not a WebP image.");
            }
            case "svg" -> {
                if (bytes.length > MAX_SVG_BYTES) {
                    yield Optional.of("An SVG image may be at most 256 KB.");
                }
                yield SvgValidator.problem(bytes);
            }
            default -> Optional.of("Unsupported file type.");
        };
    }

    private static boolean isWoff2(final byte[] b) {
        if (b.length < 48 || !startsWith(b, 0, "wOF2".getBytes(StandardCharsets.US_ASCII))) {
            return false;
        }
        final long declared = ((b[8] & 0xffL) << 24) | ((b[9] & 0xffL) << 16) | ((b[10] & 0xffL) << 8) | (b[11] & 0xffL);
        return declared == b.length;
    }

    private static boolean isPng(final byte[] b) {
        return b.length >= 16 && startsWith(b, 0, PNG) && startsWith(b, 12, "IHDR".getBytes(StandardCharsets.US_ASCII));
    }

    private static boolean isWebp(final byte[] b) {
        if (b.length < 20 || !startsWith(b, 0, "RIFF".getBytes(StandardCharsets.US_ASCII))
                || !startsWith(b, 8, "WEBP".getBytes(StandardCharsets.US_ASCII))) {
            return false;
        }
        final String chunk = new String(b, 12, 4, StandardCharsets.US_ASCII);
        return "VP8 ".equals(chunk) || "VP8L".equals(chunk) || "VP8X".equals(chunk);
    }

    private static boolean startsWith(final byte[] b, final int offset, final byte[] prefix) {
        if (b.length < offset + prefix.length) {
            return false;
        }
        for (int i = 0; i < prefix.length; i++) {
            if (b[offset + i] != prefix[i]) {
                return false;
            }
        }
        return true;
    }

    /** The lower-case extension after the last dot of a non-empty base name, or null. */
    static String extension(final String filename) {
        if (filename == null) {
            return null;
        }
        final String base = filename.substring(Math.max(filename.lastIndexOf('/'), filename.lastIndexOf('\\')) + 1);
        final int dot = base.lastIndexOf('.');
        if (dot <= 0 || dot == base.length() - 1) {
            return null;
        }
        final String ext = base.substring(dot + 1);
        return EXTENSION.matcher(ext).matches() ? ext.toLowerCase(Locale.ROOT) : null;
    }

    /** A display name from the file name: unsafe characters become '-', trimmed to the name rule. */
    private static String nameFromFile(final String filename) {
        final String base = filename.substring(Math.max(filename.lastIndexOf('/'), filename.lastIndexOf('\\')) + 1);
        String stem = base.substring(0, Math.max(base.lastIndexOf('.'), 0)).replaceAll("[^A-Za-z0-9 ._-]", "-");
        stem = stem.replaceFirst("^[^A-Za-z0-9]+", "");
        if (stem.length() > 64) {
            stem = stem.substring(0, 64);
        }
        stem = stem.stripTrailing();
        return stem.isEmpty() ? "image" : stem;
    }

    private static String blankToNull(final String s) {
        return s == null || s.isBlank() ? null : s;
    }
}
