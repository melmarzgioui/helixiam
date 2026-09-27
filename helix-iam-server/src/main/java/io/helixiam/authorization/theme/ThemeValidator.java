/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.theme;

import java.util.Collection;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;
import java.util.regex.Pattern;

/**
 * Validates one theme layer (spec §1, §4). Returns field-level errors keyed by the JSON path of the offending field
 * ({@code colors.primary.light}, {@code assets.logoUrl}, {@code customCss}, …); an empty map means valid.
 *
 * <ul>
 *   <li>Colours: exactly {@code #RRGGBB}.</li>
 *   <li>Typography: a built-in stack ({@link ThemeDefaults#BUILT_IN_FONTS}) or a font uploaded to the realm
 *       ({@link ThemeAssetCatalog#hasFont}); {@code baseSize} 14–18.</li>
 *   <li>Shape: {@code radius} 0–16, {@code density} {@code comfortable}|{@code compact}.</li>
 *   <li>Assets: {@code https} URL or one of the realm's own uploaded images; links: {@code https} only.</li>
 *   <li>Layout: {@code split}|{@code centered}; 1–20 distinct BCP-47 locales.</li>
 *   <li>Texts: plain text (no {@code <} or {@code >}, no control characters), length limits, locale keys.</li>
 *   <li>Custom CSS: realm layer only, {@link CustomCssValidator}.</li>
 *   <li>Contrast: on the effective theme ({@code below} + candidate, dark values derived), WCAG AA 4.5:1 for
 *       {@code contrast.inkOnSurface.*} (ink on surface) and {@code contrast.textOnPrimary.*} (surfaceRaised text
 *       on primary), light and dark — but only for pairs whose colours the candidate layer sets, so a layer that does
 *       not touch colours is never blamed for the layers below it.</li>
 * </ul>
 */
public class ThemeValidator {

    /** Which layer is being validated. Custom CSS is realm-only. */
    public enum Scope { REALM, ORGANIZATION }

    public static final int MAX_LOCALES = 20;
    public static final int MAX_BADGES = 8;
    public static final int MAX_BADGE_LENGTH = 40;

    private static final Pattern FONT_NAME = Pattern.compile("[A-Za-z0-9][A-Za-z0-9 _.-]{0,63}");
    private static final Pattern LOCALE = Pattern.compile("[a-z]{2,3}(-[A-Za-z0-9]{2,8}){0,3}");
    private static final Pattern CONTROL = Pattern.compile("[\\p{Cntrl}&&[^\\n]]");
    private static final Map<String, Integer> TEXT_LIMITS = Map.of("brandHeadline", 120, "brandSubhead", 240,
            "brandByline", 120, "welcomeText", 500, "footerText", 500);

    private final ThemeAssetCatalog catalog;
    private final Set<String> allowedImageOrigins;

    public ThemeValidator(final ThemeAssetCatalog catalog, final Collection<String> allowedImageOrigins) {
        this.catalog = catalog == null ? ThemeAssetCatalog.NONE : catalog;
        this.allowedImageOrigins = allowedImageOrigins == null ? Set.of() : Set.copyOf(allowedImageOrigins);
    }

    /**
     * Errors of {@code candidate} for {@code realmId}; {@code below} is the merge of every layer under it (at least
     * {@link ThemeDefaults#THEME}), used for the contrast checks and the custom-CSS origin allowlist.
     */
    public Map<String, String> validate(final String realmId, final Scope scope, final Theme candidate,
                                        final Theme below) {
        final Map<String, String> errors = new LinkedHashMap<>();
        if (candidate == null) {
            return errors;
        }
        final boolean coloursOk = colours(candidate.colors(), errors);
        typography(realmId, candidate.typography(), errors);
        shape(candidate.shape(), errors);
        assets(realmId, candidate.assets(), errors);
        layout(candidate.layout(), errors);
        texts(candidate.texts(), errors);
        links(candidate.links(), errors);
        final Theme merged = ThemeMerger.merge(below == null ? ThemeDefaults.THEME : below, candidate);
        if (candidate.customCss() != null && !candidate.customCss().isBlank()) {
            if (scope == Scope.ORGANIZATION) {
                errors.put("customCss", "Custom CSS can only be set on the realm theme.");
            } else {
                CustomCssValidator.validate(candidate.customCss(), realmId, imageOrigins(merged))
                        .ifPresent(m -> errors.put("customCss", m));
            }
        }
        if (coloursOk && candidate.colors() != null) {
            contrast(candidate.colors(), DarkPalette.resolve(merged).colors(), errors);
        }
        return errors;
    }

    /** The image origins a theme may load from: the configured allowlist plus the theme's own https asset origins. */
    public Set<String> imageOrigins(final Theme merged) {
        final Set<String> out = new LinkedHashSet<>(allowedImageOrigins);
        final ThemeAssets a = merged == null ? null : merged.assets();
        if (a != null) {
            for (final String url : new String[] {a.logoUrl(), a.logoDarkUrl(), a.faviconUrl(), a.brandImageUrl()}) {
                final String origin = ThemeUrls.httpsOrigin(url);
                if (origin != null) {
                    out.add(origin);
                }
            }
        }
        return out;
    }

    private static boolean colours(final ThemeColors colors, final Map<String, String> errors) {
        if (colors == null) {
            return true;
        }
        boolean ok = true;
        for (final String role : ThemeColors.ROLES) {
            final ThemeColor c = colors.role(role);
            if (c == null) {
                continue;
            }
            if (c.light() != null && !ThemeColorMath.isHex(c.light())) {
                errors.put("colors." + role + ".light", "Colour must be #RRGGBB.");
                ok = false;
            }
            if (c.dark() != null && !ThemeColorMath.isHex(c.dark())) {
                errors.put("colors." + role + ".dark", "Colour must be #RRGGBB.");
                ok = false;
            }
        }
        return ok;
    }

    private void typography(final String realmId, final ThemeTypography t, final Map<String, String> errors) {
        if (t == null) {
            return;
        }
        font(realmId, "typography.fontSans", t.fontSans(), errors);
        font(realmId, "typography.fontDisplay", t.fontDisplay(), errors);
        if (t.baseSize() != null && (t.baseSize() < 14 || t.baseSize() > 18)) {
            errors.put("typography.baseSize", "Base size must be between 14 and 18 px.");
        }
    }

    private void font(final String realmId, final String field, final String font, final Map<String, String> errors) {
        if (font == null) {
            return;
        }
        if (ThemeDefaults.BUILT_IN_FONTS.contains(font)) {
            return;
        }
        if (!FONT_NAME.matcher(font).matches() || !catalog.hasFont(realmId, font)) {
            errors.put(field, "Font must be system-sans, system-serif, system-mono or the name of a font uploaded "
                    + "to this realm.");
        }
    }

    private static void shape(final ThemeShape s, final Map<String, String> errors) {
        if (s == null) {
            return;
        }
        if (s.radius() != null && (s.radius() < 0 || s.radius() > 16)) {
            errors.put("shape.radius", "Radius must be between 0 and 16 px.");
        }
        if (s.density() != null && !List.of("comfortable", "compact").contains(s.density())) {
            errors.put("shape.density", "Density must be comfortable or compact.");
        }
    }

    private void assets(final String realmId, final ThemeAssets a, final Map<String, String> errors) {
        if (a == null) {
            return;
        }
        asset(realmId, "assets.logoUrl", a.logoUrl(), errors);
        asset(realmId, "assets.logoDarkUrl", a.logoDarkUrl(), errors);
        asset(realmId, "assets.faviconUrl", a.faviconUrl(), errors);
        asset(realmId, "assets.brandImageUrl", a.brandImageUrl(), errors);
    }

    private void asset(final String realmId, final String field, final String url, final Map<String, String> errors) {
        if (url == null || ThemeUrls.isHttps(url)) {
            return;
        }
        final boolean own = ThemeUrls.parseAsset(url)
                .filter(ref -> ref.realmId().equals(realmId))
                .filter(ref -> ThemeUrls.IMAGE_EXTENSIONS.contains(ref.extension()))
                .filter(ref -> catalog.hasAsset(realmId, ref.assetId(), ref.extension()))
                .isPresent();
        if (!own) {
            errors.put(field, "Must be an https URL or one of this realm's uploaded images (/realms/" + realmId
                    + "/theme/assets/{id}.{svg|png|webp}).");
        }
    }

    private static void layout(final ThemeLayout l, final Map<String, String> errors) {
        if (l == null) {
            return;
        }
        if (l.layout() != null && !List.of("split", "centered").contains(l.layout())) {
            errors.put("layout.layout", "Layout must be split or centered.");
        }
        final List<String> locales = l.supportedLocales();
        if (locales != null) {
            if (locales.isEmpty() || locales.size() > MAX_LOCALES) {
                errors.put("layout.supportedLocales", "Give between 1 and " + MAX_LOCALES + " locales.");
            } else if (locales.stream().anyMatch(x -> x == null || !LOCALE.matcher(x).matches())
                    || new HashSet<>(locales).size() != locales.size()) {
                errors.put("layout.supportedLocales", "Locales must be distinct language tags such as en, nl or pt-BR.");
            }
        }
    }

    private static void texts(final ThemeTexts t, final Map<String, String> errors) {
        if (t == null) {
            return;
        }
        text("brandHeadline", t.brandHeadline(), errors);
        text("brandSubhead", t.brandSubhead(), errors);
        text("brandByline", t.brandByline(), errors);
        text("welcomeText", t.welcomeText(), errors);
        text("footerText", t.footerText(), errors);
        if (t.brandBadges() != null) {
            final String field = "texts.brandBadges";
            if (!localeKeysOk(t.brandBadges().values().keySet())) {
                errors.put(field, "Keys must be 'default' or language tags such as en or pt-BR.");
                return;
            }
            for (final List<String> badges : t.brandBadges().values().values()) {
                if (badges.size() > MAX_BADGES) {
                    errors.put(field, "At most " + MAX_BADGES + " badges.");
                    return;
                }
                for (final String b : badges) {
                    final String problem = plainText(b, MAX_BADGE_LENGTH);
                    if (problem != null) {
                        errors.put(field, "Badge: " + problem);
                        return;
                    }
                }
            }
        }
    }

    private static void text(final String name, final LocalizedText value, final Map<String, String> errors) {
        if (value == null) {
            return;
        }
        final String field = "texts." + name;
        if (!localeKeysOk(value.values().keySet())) {
            errors.put(field, "Keys must be 'default' or language tags such as en or pt-BR.");
            return;
        }
        for (final String v : value.values().values()) {
            final String problem = plainText(v, TEXT_LIMITS.get(name));
            if (problem != null) {
                errors.put(field, problem);
                return;
            }
        }
    }

    private static boolean localeKeysOk(final Set<String> keys) {
        return keys.size() <= MAX_LOCALES + 1
                && keys.stream().allMatch(k -> LocalizedText.DEFAULT.equals(k) || (k != null && LOCALE.matcher(k).matches()));
    }

    /** Null when {@code v} is acceptable plain text of at most {@code max} characters. */
    static String plainText(final String v, final int max) {
        if (v == null) {
            return "Text must not be null.";
        }
        if (v.length() > max) {
            return "Text must be at most " + max + " characters.";
        }
        if (v.indexOf('<') >= 0 || v.indexOf('>') >= 0) {
            return "Text is plain text and cannot contain < or >.";
        }
        if (CONTROL.matcher(v).find()) {
            return "Text cannot contain control characters.";
        }
        return null;
    }

    private static void links(final ThemeLinks l, final Map<String, String> errors) {
        if (l == null) {
            return;
        }
        link("links.privacyUrl", l.privacyUrl(), errors);
        link("links.termsUrl", l.termsUrl(), errors);
        link("links.supportUrl", l.supportUrl(), errors);
    }

    private static void link(final String field, final String url, final Map<String, String> errors) {
        if (url != null && !ThemeUrls.isHttps(url)) {
            errors.put(field, "Must be an https URL.");
        }
    }

    private static void contrast(final ThemeColors candidate, final ThemeColors effective,
                                 final Map<String, String> errors) {
        pair(candidate, effective, "inkOnSurface", "Ink on surface", "ink", "surface", errors);
        pair(candidate, effective, "textOnPrimary", "Text on primary", "surfaceRaised", "primary", errors);
    }

    private static void pair(final ThemeColors candidate, final ThemeColors effective, final String key,
                             final String label, final String fg, final String bg, final Map<String, String> errors) {
        if (candidate.role(fg) == null && candidate.role(bg) == null) {
            return;
        }
        variant(effective, key, label, fg, bg, "light", ThemeColor::light, errors);
        variant(effective, key, label, fg, bg, "dark", ThemeColor::dark, errors);
    }

    private static void variant(final ThemeColors effective, final String key, final String label, final String fg,
                                final String bg, final String variant, final Function<ThemeColor, String> pick,
                                final Map<String, String> errors) {
        final String f = pick.apply(effective.role(fg));
        final String b = pick.apply(effective.role(bg));
        final double ratio = ThemeColorMath.contrast(f, b);
        if (ratio < ThemeColorMath.AA_TEXT) {
            errors.put("contrast." + key + "." + variant, String.format(Locale.ROOT,
                    "%s (%s): %s %s on %s %s has a contrast of %s; WCAG AA needs at least 4.5:1.",
                    label, variant, fg, f, bg, b, ThemeColorMath.ratio(ratio)));
        }
    }
}
