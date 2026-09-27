/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.theme;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Derives the dark variant of every colour that has none (spec §1: dark values are optional). The hue of the
 * light value is kept; lightness and saturation move to the dark scheme — surfaces become near-black, ink
 * near-white, brand colours lighter — and derived foreground colours are nudged until they meet WCAG AA against
 * the dark surface they sit on. Explicit dark values are never changed.
 *
 * <p>"Text on primary" uses {@code surfaceRaised} as the text colour (white-ish in light, near-black in dark), so a
 * derived dark primary is checked against the dark {@code surfaceRaised}.
 */
public final class DarkPalette {

    private DarkPalette() {
    }

    /** {@code merged} with every missing dark value derived (and missing light values taken from the defaults). */
    public static Theme resolve(final Theme merged) {
        final ThemeColors in = merged.colors() == null ? ThemeDefaults.THEME.colors() : merged.colors();
        final Map<String, ThemeColor> out = new LinkedHashMap<>();
        // Neutrals first: brand colours are derived against the dark surfaces.
        for (final String role : new String[] {"surface", "surfaceRaised", "surfaceSunken", "border", "ink", "inkMuted",
                "primary", "primaryStrong", "primaryTint", "negative", "negativeTint", "positive", "positiveTint",
                "focusRing"}) {
            final ThemeColor c = complete(role, in.role(role));
            if (c.dark() != null) {
                out.put(role, c);
                continue;
            }
            String dark = derive(role, c.light());
            final String against = switch (role) {
                case "ink" -> out.get("surface").dark();
                case "inkMuted", "negative", "positive" -> out.get("surface").dark();
                case "primary", "primaryStrong" -> out.get("surfaceRaised").dark();
                default -> null;
            };
            if (against != null) {
                dark = ThemeColorMath.ensureContrast(dark, against, ThemeColorMath.AA_TEXT);
            }
            if ("inkMuted".equals(role)) {
                // Item 7a: muted text also sits on cards and fields (the raised surface, lighter in dark mode).
                dark = ThemeColorMath.ensureContrast(dark, out.get("surfaceRaised").dark(), ThemeColorMath.AA_TEXT);
            }
            out.put(role, new ThemeColor(c.light(), dark));
        }
        return merged.withColors(ThemeColors.from(out::get));
    }

    private static ThemeColor complete(final String role, final ThemeColor c) {
        final ThemeColor fallback = ThemeDefaults.THEME.colors().role(role);
        if (c == null) {
            return fallback;
        }
        if (c.light() == null) {
            return new ThemeColor(fallback.light(), c.dark() != null ? c.dark() : fallback.dark());
        }
        return c;
    }

    /** The derived dark value of {@code role} for the light value {@code light}. */
    public static String derive(final String role, final String light) {
        final double[] hsl = ThemeColorMath.toHsl(light);
        final double h = hsl[0];
        final double s = hsl[1];
        final double mirrored = clamp(1 - hsl[2], 0.58, 0.80);
        return switch (role) {
            case "surface" -> ThemeColorMath.fromHsl(h, Math.min(s, 0.25), 0.07);
            case "surfaceRaised" -> ThemeColorMath.fromHsl(h, Math.min(s, 0.22), 0.11);
            case "surfaceSunken" -> ThemeColorMath.fromHsl(h, Math.min(s, 0.25), 0.045);
            case "border" -> ThemeColorMath.fromHsl(h, Math.min(s, 0.18), 0.22);
            case "ink" -> ThemeColorMath.fromHsl(h, Math.min(s, 0.18), 0.92);
            case "inkMuted" -> ThemeColorMath.fromHsl(h, Math.min(s, 0.14), 0.70);
            case "primary", "negative", "positive", "focusRing" -> ThemeColorMath.fromHsl(h, Math.min(s, 0.75), mirrored);
            case "primaryStrong" -> ThemeColorMath.fromHsl(h, Math.min(s, 0.75), Math.min(0.9, mirrored + 0.08));
            case "primaryTint", "negativeTint", "positiveTint" -> ThemeColorMath.fromHsl(h, Math.min(s, 0.35), 0.15);
            default -> throw new IllegalArgumentException("Unknown colour role " + role);
        };
    }

    private static double clamp(final double v, final double min, final double max) {
        return Math.max(min, Math.min(max, v));
    }
}
