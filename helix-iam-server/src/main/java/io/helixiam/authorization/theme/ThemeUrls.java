/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.theme;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * URL rules for themes: absolute {@code https} URLs that are safe inside an HTML attribute and a CSS
 * {@code url()}, and the realm's own uploaded assets at {@code /realms/{realm}/theme/assets/{id}.{ext}}.
 */
public final class ThemeUrls {

    /** Longest URL accepted. */
    public static final int MAX_LENGTH = 2048;

    /** Image extensions an asset URL may carry (fonts are referenced by name, not URL). */
    public static final Set<String> IMAGE_EXTENSIONS = Set.of("svg", "png", "webp");

    private static final Pattern UNSAFE = Pattern.compile("[\\s\"'<>()\\\\`{}|^]");
    private static final Pattern ASSET = Pattern.compile("/realms/([A-Za-z0-9._-]+)/theme/assets/([A-Za-z0-9_-]{1,64})\\.([a-z0-9]{2,5})");

    private ThemeUrls() {
    }

    /** A reference to an uploaded asset parsed from its URL. */
    public record AssetRef(String realmId, String assetId, String extension) {
    }

    /** The public path of an uploaded asset (Task 2 serves it). */
    public static String assetPath(final String realmId, final String assetId, final String extension) {
        return "/realms/" + realmId + "/theme/assets/" + assetId + "." + extension;
    }

    /** Parses {@code /realms/{realm}/theme/assets/{id}.{ext}}; empty for anything else. */
    public static Optional<AssetRef> parseAsset(final String url) {
        if (url == null) {
            return Optional.empty();
        }
        final Matcher m = ASSET.matcher(url);
        return m.matches() ? Optional.of(new AssetRef(m.group(1), m.group(2), m.group(3))) : Optional.empty();
    }

    /** True for an absolute {@code https} URL with a host, no user info, and no characters unsafe in HTML/CSS. */
    public static boolean isHttps(final String url) {
        return httpsOrigin(url) != null;
    }

    /** {@code https://host[:port]} (lower-case) of a valid https URL, or null. */
    public static String httpsOrigin(final String url) {
        if (url == null || url.length() > MAX_LENGTH || UNSAFE.matcher(url).find()) {
            return null;
        }
        try {
            final URI uri = new URI(url);
            if (!"https".equalsIgnoreCase(uri.getScheme()) || uri.getRawAuthority() == null
                    || uri.getRawUserInfo() != null || uri.getHost() == null || uri.getHost().isBlank()) {
                return null;
            }
            final String host = uri.getHost().toLowerCase(Locale.ROOT);
            return "https://" + host + (uri.getPort() > 0 && uri.getPort() != 443 ? ":" + uri.getPort() : "");
        } catch (final URISyntaxException e) {
            return null;
        }
    }

    /** Normalises an origin from configuration ({@code https://Img.Example/} → {@code https://img.example}). */
    public static String normalizeOrigin(final String origin) {
        if (origin == null || origin.isBlank()) {
            return null;
        }
        return httpsOrigin(origin.trim().endsWith("/") ? origin.trim() : origin.trim() + "/");
    }
}
