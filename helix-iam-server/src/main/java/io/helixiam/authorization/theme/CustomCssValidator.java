/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.theme;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * The restricted custom-CSS escape hatch (spec §4). Accepts plain CSS only, at most {@value #MAX_BYTES} bytes, and
 * rejects — naming the offending construct — {@code <} (no {@code </style>} breakout), {@code @import},
 * {@code @charset}, {@code @namespace}, {@code expression(}, {@code behavior:}, {@code -moz-binding},
 * {@code javascript:}, and any {@code url(} whose target is not the realm's own theme assets
 * ({@code /realms/{realm}/theme/assets/...}) or an allowlisted image origin. {@code image-set(} and {@code src(}
 * (other ways to fetch a URL) are rejected too.
 *
 * <p>Checks run on a normalised copy of the CSS — comments removed and CSS escapes decoded — so obfuscations such
 * as {@code @im/&#42;&#42;/port} or {@code @\69mport} are caught. Pure and static so the Flyway data migration, the
 * admin API, import, and the {@code theme.css} renderer all apply exactly the same rules.
 */
public final class CustomCssValidator {

    /** 32 KB cap (UTF-8 bytes). */
    public static final int MAX_BYTES = 32 * 1024;

    /** Shown by the admin API whenever custom CSS is set (spec §4). */
    public static final String NOTICE = "Custom CSS depends on HelixIAM's internal page markup and may break across "
            + "versions. Prefer the structured theme settings (colours, typography, shape, assets, layout, texts).";

    private static final Pattern COMMENT = Pattern.compile("/\\*.*?(\\*/|\\z)", Pattern.DOTALL);
    private static final Pattern HEX_ESCAPE = Pattern.compile("\\\\([0-9a-fA-F]{1,6})[ \\t\\n\\r\\f]?");
    private static final Pattern CHAR_ESCAPE = Pattern.compile("\\\\([^0-9a-fA-F\\n\\r\\f])");
    private static final Pattern URL_FN = Pattern.compile("url\\s*\\(\\s*(\"([^\"]*)\"|'([^']*)'|([^)\\s]*))\\s*\\)?",
            Pattern.CASE_INSENSITIVE);
    private static final Pattern ASSET_PATH = Pattern.compile("/realms/([A-Za-z0-9._-]+)/theme/assets/[A-Za-z0-9_-]{1,64}\\.[a-z0-9]{2,5}");

    /** Forbidden constructs: regex on the normalised, lower-cased CSS, and the name reported. */
    private static final List<Forbidden> FORBIDDEN = List.of(
            new Forbidden(Pattern.compile("<"), "<"),
            new Forbidden(Pattern.compile("@import"), "@import"),
            new Forbidden(Pattern.compile("@charset"), "@charset"),
            new Forbidden(Pattern.compile("@namespace"), "@namespace"),
            new Forbidden(Pattern.compile("expression\\s*\\("), "expression("),
            new Forbidden(Pattern.compile("behavior\\s*:"), "behavior:"),
            new Forbidden(Pattern.compile("-moz-binding"), "-moz-binding"),
            new Forbidden(Pattern.compile("javascript\\s*:"), "javascript:"),
            new Forbidden(Pattern.compile("image-set\\s*\\("), "image-set("),
            new Forbidden(Pattern.compile("(?<![a-z0-9_-])src\\s*\\("), "src("));

    private CustomCssValidator() {
    }

    /** The first problem with {@code css}, or empty when it is acceptable (null/blank is acceptable). */
    public static Optional<String> validate(final String css, final String realmId,
                                            final Collection<String> allowedImageOrigins) {
        return problems(css, realmId, allowedImageOrigins).stream().findFirst();
    }

    /** Every problem with {@code css}, in the order checked. */
    public static List<String> problems(final String css, final String realmId,
                                        final Collection<String> allowedImageOrigins) {
        final List<String> out = new ArrayList<>();
        if (css == null || css.isBlank()) {
            return out;
        }
        if (css.getBytes(StandardCharsets.UTF_8).length > MAX_BYTES) {
            out.add("Custom CSS must be at most 32 KB.");
            return out;
        }
        final String normalized = normalize(css);
        final String lower = normalized.toLowerCase(Locale.ROOT);
        for (final Forbidden f : FORBIDDEN) {
            if (f.pattern().matcher(lower).find()) {
                out.add("Custom CSS must not contain " + f.name() + ".");
            }
        }
        final Matcher url = URL_FN.matcher(normalized);
        while (url.find()) {
            final String target = firstNonNull(url.group(2), url.group(3), url.group(4)).trim();
            if (!allowedTarget(target, realmId, allowedImageOrigins)) {
                out.add("Custom CSS url( may only point at this realm's theme assets (/realms/" + realmId
                        + "/theme/assets/...) or an allowlisted image origin, not: " + abbreviate(target));
            }
        }
        return out;
    }

    /** True when {@code target} is this realm's own asset or on an allowlisted {@code https} origin. */
    static boolean allowedTarget(final String target, final String realmId, final Collection<String> origins) {
        final Matcher asset = ASSET_PATH.matcher(target);
        if (asset.matches()) {
            return asset.group(1).equals(realmId);
        }
        final String origin = ThemeUrls.httpsOrigin(target);
        return origin != null && origins != null && origins.contains(origin);
    }

    /** Comments removed and CSS escapes decoded. */
    static String normalize(final String css) {
        final String noComments = COMMENT.matcher(css).replaceAll("");
        final Matcher hex = HEX_ESCAPE.matcher(noComments);
        final StringBuilder sb = new StringBuilder();
        while (hex.find()) {
            final int cp = Integer.parseInt(hex.group(1), 16);
            final String decoded = cp == 0 || cp > Character.MAX_CODE_POINT || (cp >= 0xD800 && cp <= 0xDFFF)
                    ? "\uFFFD" : new String(Character.toChars(cp));
            hex.appendReplacement(sb, Matcher.quoteReplacement(decoded));
        }
        hex.appendTail(sb);
        return CHAR_ESCAPE.matcher(sb.toString()).replaceAll("$1");
    }

    private static String firstNonNull(final String... values) {
        for (final String v : values) {
            if (v != null) {
                return v;
            }
        }
        return "";
    }

    private static String abbreviate(final String s) {
        return s.length() > 80 ? s.substring(0, 80) + "…" : s;
    }

    private record Forbidden(Pattern pattern, String name) {
    }
}
