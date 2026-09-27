/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.theme;

import java.util.Locale;
import java.util.regex.Pattern;

/**
 * Colour arithmetic for themes: {@code #RRGGBB} parsing, WCAG 2.x relative luminance and contrast ratio, and HSL
 * conversions used to derive dark variants.
 */
public final class ThemeColorMath {

    /** WCAG AA minimum contrast for normal text. */
    public static final double AA_TEXT = 4.5;

    private static final Pattern HEX = Pattern.compile("#[0-9a-fA-F]{6}");

    private ThemeColorMath() {
    }

    /** True for exactly {@code #RRGGBB}. */
    public static boolean isHex(final String value) {
        return value != null && HEX.matcher(value).matches();
    }

    /** Lower-cases a valid hex colour (null stays null). */
    public static String normalize(final String hex) {
        return hex == null ? null : hex.toLowerCase(Locale.ROOT);
    }

    /** WCAG relative luminance of {@code #RRGGBB}. */
    public static double luminance(final String hex) {
        final int rgb = Integer.parseInt(hex.substring(1), 16);
        return 0.2126 * channel((rgb >> 16) & 0xff) + 0.7152 * channel((rgb >> 8) & 0xff) + 0.0722 * channel(rgb & 0xff);
    }

    private static double channel(final int v) {
        final double c = v / 255.0;
        return c <= 0.03928 ? c / 12.92 : Math.pow((c + 0.055) / 1.055, 2.4);
    }

    /** WCAG contrast ratio between two colours (1–21). */
    public static double contrast(final String a, final String b) {
        final double la = luminance(a);
        final double lb = luminance(b);
        return (Math.max(la, lb) + 0.05) / (Math.min(la, lb) + 0.05);
    }

    /** {@code #RRGGBB} to {h (0–360), s (0–1), l (0–1)}. */
    public static double[] toHsl(final String hex) {
        final int rgb = Integer.parseInt(hex.substring(1), 16);
        final double r = ((rgb >> 16) & 0xff) / 255.0;
        final double g = ((rgb >> 8) & 0xff) / 255.0;
        final double b = (rgb & 0xff) / 255.0;
        final double max = Math.max(r, Math.max(g, b));
        final double min = Math.min(r, Math.min(g, b));
        final double l = (max + min) / 2;
        if (max == min) {
            return new double[] {0, 0, l};
        }
        final double d = max - min;
        final double s = l > 0.5 ? d / (2 - max - min) : d / (max + min);
        final double h;
        if (max == r) {
            h = ((g - b) / d + (g < b ? 6 : 0)) * 60;
        } else if (max == g) {
            h = ((b - r) / d + 2) * 60;
        } else {
            h = ((r - g) / d + 4) * 60;
        }
        return new double[] {h, s, l};
    }

    /** HSL to lower-case {@code #rrggbb}; s and l are clamped to 0–1. */
    public static String fromHsl(final double h, final double s, final double l) {
        final double sc = clamp(s);
        final double lc = clamp(l);
        final double c = (1 - Math.abs(2 * lc - 1)) * sc;
        final double hp = ((h % 360) + 360) % 360 / 60.0;
        final double x = c * (1 - Math.abs(hp % 2 - 1));
        final double[] rgb;
        if (hp < 1) {
            rgb = new double[] {c, x, 0};
        } else if (hp < 2) {
            rgb = new double[] {x, c, 0};
        } else if (hp < 3) {
            rgb = new double[] {0, c, x};
        } else if (hp < 4) {
            rgb = new double[] {0, x, c};
        } else if (hp < 5) {
            rgb = new double[] {x, 0, c};
        } else {
            rgb = new double[] {c, 0, x};
        }
        final double m = lc - c / 2;
        return String.format(Locale.ROOT, "#%02x%02x%02x", round(rgb[0] + m), round(rgb[1] + m), round(rgb[2] + m));
    }

    private static int round(final double v) {
        return (int) Math.round(clamp(v) * 255);
    }

    static double clamp(final double v) {
        return Math.max(0, Math.min(1, v));
    }

    /**
     * Moves {@code color}'s lightness away from {@code against} until the pair reaches {@code minRatio} (or the
     * lightness runs out); returns the adjusted colour.
     */
    public static String ensureContrast(final String color, final String against, final double minRatio) {
        if (contrast(color, against) >= minRatio) {
            return color;
        }
        final double[] hsl = toHsl(color);
        final boolean lighten = luminance(against) < 0.18;
        String best = color;
        for (double l = hsl[2]; l >= 0 && l <= 1; l += lighten ? 0.02 : -0.02) {
            best = fromHsl(hsl[0], hsl[1], l);
            if (contrast(best, against) >= minRatio) {
                return best;
            }
        }
        return lighten ? fromHsl(hsl[0], hsl[1], 1) : fromHsl(hsl[0], hsl[1], 0);
    }

    /** Formats a ratio as {@code 3.2:1}. */
    public static String ratio(final double r) {
        return String.format(Locale.ROOT, "%.1f:1", Math.floor(r * 10) / 10);
    }
}
