/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.theme;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * The restricted custom-CSS escape hatch (spec §4). Strict rather than clever: every check runs on the RAW input,
 * never on a normalised copy, so what is checked is exactly what an HTML parser and a CSS tokenizer will see.
 *
 * <p>Rejected, each with a message naming the construct:
 * <ul>
 *   <li>more than {@value #MAX_BYTES} bytes;</li>
 *   <li>any {@code <} (no {@code </style>} breakout, whatever the CSS context);</li>
 *   <li>any backslash — no CSS escapes at all, so names and URLs cannot be disguised;</li>
 *   <li>any comment ({@code /*}) — comments do not exist for the HTML parser and can hide payloads;</li>
 *   <li>NUL and other control characters except tab, LF, CR and FF;</li>
 *   <li>{@code @import}, {@code @charset}, {@code @namespace}, {@code expression(}, {@code behavior:},
 *       {@code -moz-binding}, {@code javascript:} (ASCII case-insensitive);</li>
 *   <li>the other URL-fetching functions {@code image-set(}, {@code -webkit-image-set(}, {@code image(},
 *       {@code cross-fade(}, {@code src(};</li>
 *   <li>any {@code url(…)} (quoted or unquoted) whose target is not exactly one of the realm's own theme assets
 *       ({@code /realms/{realm}/theme/assets/{id}.{ext}}) or an https URL on an origin the OPERATOR allowlisted
 *       ({@code helix.theme.allowed-image-origins}). URLs a realm admin can set elsewhere in the theme (logo,
 *       favicon, …) never widen this list.</li>
 * </ul>
 *
 * Pure and static, so the Flyway data migration, the admin API, import and the effective-theme resolver apply the
 * same rules.
 */
public final class CustomCssValidator {

    /** 32 KB cap (UTF-8 bytes). */
    public static final int MAX_BYTES = 32 * 1024;

    /** Shown by the admin API whenever custom CSS is set (spec §4). */
    public static final String NOTICE = "Custom CSS depends on HelixIAM's internal page markup and may break across "
            + "versions. Prefer the structured theme settings (colours, typography, shape, assets, layout, texts).";

    private static final Pattern ASSET_PATH =
            Pattern.compile("/realms/([A-Za-z0-9._-]+)/theme/assets/([A-Za-z0-9_-]{1,64})\\.([a-z0-9]{2,5})");
    /**
     * Every pattern is matched against the RAW input with {@link Pattern#CASE_INSENSITIVE} and without
     * {@code UNICODE_CASE}: ASCII-only case folding, exactly like CSS keywords, independent of the default locale,
     * and — crucially — without changing string length. Never match on a lower-cased copy and index the raw string
     * with the result (re-review R1: U+0130 lower-cases to two chars and shifted the url() parser).
     */
    private static final int ASCII_CI = Pattern.CASE_INSENSITIVE;

    /** {@code url(} with optional whitespace; the name may not continue an identifier. */
    private static final Pattern URL_START = Pattern.compile("(?<![a-z0-9_-])url\\s*\\(", ASCII_CI);
    private static final Pattern FETCH_FUNCTION = Pattern.compile(
            "(?<![a-z0-9_-])(-webkit-image-set|image-set|image|-webkit-cross-fade|cross-fade|src)\\s*\\(", ASCII_CI);

    private static final List<Forbidden> FORBIDDEN = List.of(
            new Forbidden(Pattern.compile("@import", ASCII_CI), "@import"),
            new Forbidden(Pattern.compile("@charset", ASCII_CI), "@charset"),
            new Forbidden(Pattern.compile("@namespace", ASCII_CI), "@namespace"),
            new Forbidden(Pattern.compile("expression\\s*\\(", ASCII_CI), "expression("),
            new Forbidden(Pattern.compile("behavior\\s*:", ASCII_CI), "behavior:"),
            new Forbidden(Pattern.compile("-moz-binding", ASCII_CI), "-moz-binding"),
            new Forbidden(Pattern.compile("javascript\\s*:", ASCII_CI), "javascript:"));

    private CustomCssValidator() {
    }

    /** The first problem with {@code css}, or empty when it is acceptable (null/blank is acceptable). */
    public static Optional<String> validate(final String css, final String realmId,
                                            final Collection<String> operatorImageOrigins) {
        return problems(css, realmId, operatorImageOrigins).stream().findFirst();
    }

    /** Every problem with {@code css}; own-asset URLs are accepted by shape only. */
    public static List<String> problems(final String css, final String realmId,
                                        final Collection<String> operatorImageOrigins) {
        return problems(css, realmId, operatorImageOrigins, null);
    }

    /**
     * Every problem with {@code css}. When {@code catalog} is given, an own-asset URL must also name an existing
     * asset of the realm.
     */
    public static List<String> problems(final String css, final String realmId,
                                        final Collection<String> operatorImageOrigins,
                                        final ThemeAssetCatalog catalog) {
        final List<String> out = new ArrayList<>();
        if (css == null || css.isBlank()) {
            return out;
        }
        if (css.getBytes(StandardCharsets.UTF_8).length > MAX_BYTES) {
            out.add("Custom CSS must be at most 32 KB.");
            return out;
        }
        if (css.indexOf('<') >= 0) {
            out.add("Custom CSS must not contain <.");
        }
        if (css.indexOf('\\') >= 0) {
            out.add("Custom CSS must not contain a backslash (CSS escapes are not allowed).");
        }
        if (css.contains("/*")) {
            out.add("Custom CSS must not contain a comment (/*).");
        }
        if (css.chars().anyMatch(CustomCssValidator::forbiddenControl)) {
            out.add("Custom CSS must not contain a control character.");
        }
        for (final Forbidden f : FORBIDDEN) {
            if (f.pattern().matcher(css).find()) {
                out.add("Custom CSS must not contain " + f.name() + ".");
            }
        }
        final Matcher fetch = FETCH_FUNCTION.matcher(css);
        while (fetch.find()) {
            final String matched = asciiLower(fetch.group(1)); // for the message only, never for indexing
            final String name = matched.startsWith("-webkit-") ? matched.substring(8) : matched;
            final String message = "Custom CSS must not contain " + name + "( — use url() with an allowed target.";
            if (!out.contains(message)) {
                out.add(message);
            }
        }
        final Matcher url = URL_START.matcher(css); // the match offsets index the same (raw) string
        while (url.find()) {
            final String problem = checkUrl(css, url.end(), realmId, operatorImageOrigins, catalog);
            if (problem != null) {
                out.add(problem);
            }
        }
        return out;
    }

    /** Tokenises one {@code url(} argument on the raw text from {@code start}; null when acceptable. */
    private static String checkUrl(final String css, final int start, final String realmId,
                                   final Collection<String> origins, final ThemeAssetCatalog catalog) {
        int i = skipWhitespace(css, start);
        final String target;
        if (i < css.length() && (css.charAt(i) == '"' || css.charAt(i) == '\'')) {
            final char quote = css.charAt(i);
            final int close = css.indexOf(quote, i + 1);
            if (close < 0) {
                return "Custom CSS url( has an unterminated string.";
            }
            target = css.substring(i + 1, close);
            if (target.chars().anyMatch(ch -> ch == '\n' || ch == '\r' || ch == '\f')) {
                return "Custom CSS url( has a line break inside its string.";
            }
            i = skipWhitespace(css, close + 1);
        } else {
            final int begin = i;
            while (i < css.length() && ")\"'( \t\n\r\f".indexOf(css.charAt(i)) < 0) {
                i++;
            }
            target = css.substring(begin, i);
            i = skipWhitespace(css, i);
        }
        if (i >= css.length() || css.charAt(i) != ')') {
            return "Custom CSS url( must contain exactly one URL followed by ).";
        }
        if (!allowedTarget(target, realmId, origins, catalog)) {
            return "Custom CSS url( may only point at this realm's theme assets (/realms/" + realmId
                    + "/theme/assets/...) or an operator-allowlisted image origin, not: " + abbreviate(target);
        }
        return null;
    }

    /** True when {@code target} is exactly this realm's own asset or an https URL on an operator-allowlisted origin. */
    static boolean allowedTarget(final String target, final String realmId, final Collection<String> origins,
                                 final ThemeAssetCatalog catalog) {
        final Matcher asset = ASSET_PATH.matcher(target);
        if (asset.matches()) {
            return asset.group(1).equals(realmId)
                    && (catalog == null || catalog.hasAsset(realmId, asset.group(2), asset.group(3)));
        }
        final String origin = ThemeUrls.httpsOrigin(target);
        return origin != null && origins != null && origins.contains(origin);
    }

    /** Lower-cases A–Z only (length-preserving, locale-independent). */
    private static String asciiLower(final String s) {
        final char[] out = s.toCharArray();
        for (int i = 0; i < out.length; i++) {
            if (out[i] >= 'A' && out[i] <= 'Z') {
                out[i] = (char) (out[i] + ('a' - 'A'));
            }
        }
        return new String(out);
    }

    private static boolean forbiddenControl(final int ch) {
        return (ch < 0x20 && ch != '\t' && ch != '\n' && ch != '\r' && ch != '\f') || (ch >= 0x7f && ch <= 0x9f);
    }

    private static int skipWhitespace(final String s, final int from) {
        int i = from;
        while (i < s.length() && " \t\n\r\f".indexOf(s.charAt(i)) >= 0) {
            i++;
        }
        return i;
    }

    private static String abbreviate(final String s) {
        return s.length() > 80 ? s.substring(0, 80) + "…" : s;
    }

    private record Forbidden(Pattern pattern, String name) {
    }
}
