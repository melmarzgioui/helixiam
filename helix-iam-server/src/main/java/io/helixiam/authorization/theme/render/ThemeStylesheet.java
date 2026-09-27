/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.theme.render;

import io.helixiam.authorization.theme.EffectiveTheme;
import io.helixiam.authorization.theme.Theme;
import io.helixiam.authorization.theme.ThemeDefaults;
import io.helixiam.authorization.theme.ThemeService;
import io.helixiam.authorization.theme.asset.ThemeAssetKind;
import io.helixiam.authorization.theme.asset.ThemeAssetService;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.LongSupplier;

/**
 * The generated {@code theme.css} of a realm (and organization), with its strong ETag. Both the stylesheet endpoint and
 * the pages (for the {@code ?v=} cache buster) use it, so a theme change reaches the pages immediately.
 *
 * <p>Rendered stylesheets are cached per realm and effective-theme version for 30 s — the same lifetime as the
 * effective theme itself — so a font upload (which does not change the theme) shows within that window.
 */
@Service
public class ThemeStylesheet {

    private static final long CACHE_TTL_MILLIS = 30_000L;
    private static final int MAX_CACHE_ENTRIES = 10_000;

    private final ThemeService themes;
    private final ObjectProvider<ThemeAssetService> assets;
    private final Map<String, Cached> cache = new ConcurrentHashMap<>();
    private final LongSupplier clock;

    @org.springframework.beans.factory.annotation.Autowired
    public ThemeStylesheet(final ThemeService themes, final ObjectProvider<ThemeAssetService> assets) {
        this(themes, assets, System::currentTimeMillis);
    }

    ThemeStylesheet(final ThemeService themes, final ObjectProvider<ThemeAssetService> assets, final LongSupplier clock) {
        this.themes = themes;
        this.assets = assets;
        this.clock = clock;
    }

    /** A rendered stylesheet and its ETag value (the SHA-256 of the bytes, hex). */
    public record Rendered(String css, String etag) {

        /** The short cache-busting version for the {@code ?v=} of the page's link. */
        public String version() {
            return etag.substring(0, 16);
        }
    }

    /** The stylesheet for {@code realmId}; {@code orgHint} is honoured only for an organization of that realm. */
    public Rendered forRealm(final String realmId, final Optional<String> orgHint) {
        final EffectiveTheme effective = themes.effectiveTheme(realmId, orgHint);
        final String key = realmId + "|" + effective.version();
        final Cached hit = cache.get(key);
        if (hit != null && clock.getAsLong() - hit.at() < CACHE_TTL_MILLIS) {
            return hit.value();
        }
        final Rendered fresh = render(effective.theme(), fonts(realmId, effective.theme()));
        if (cache.size() >= MAX_CACHE_ENTRIES) {
            cache.clear();
        }
        cache.put(key, new Cached(fresh, clock.getAsLong()));
        return fresh;
    }

    /** Renders an effective theme (no caching; the preview uses this for a proposed theme). */
    public Rendered render(final Theme effectiveTheme, final List<FontFace> fonts) {
        final String css = ThemeCssRenderer.render(effectiveTheme, fonts);
        return new Rendered(css, sha256(css));
    }

    /** The realm's uploaded font files of the families {@code theme} names (no query when it names built-ins only). */
    public List<FontFace> fonts(final String realmId, final Theme theme) {
        final String sans = theme.typography() == null ? null : theme.typography().fontSans();
        final String display = theme.typography() == null ? null : theme.typography().fontDisplay();
        final boolean uploaded = (sans != null && !ThemeDefaults.BUILT_IN_FONTS.contains(sans))
                || (display != null && !ThemeDefaults.BUILT_IN_FONTS.contains(display));
        final ThemeAssetService service = assets.getIfAvailable();
        if (!uploaded || service == null) {
            return List.of();
        }
        return service.list(realmId).stream()
                .filter(m -> m.kind() == ThemeAssetKind.FONT)
                .map(m -> new FontFace(m.name(), m.url(), m.weight(), m.style()))
                .toList();
    }

    private static String sha256(final String css) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                    .digest(css.getBytes(StandardCharsets.UTF_8)));
        } catch (final NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    private record Cached(Rendered value, long at) {
    }
}
