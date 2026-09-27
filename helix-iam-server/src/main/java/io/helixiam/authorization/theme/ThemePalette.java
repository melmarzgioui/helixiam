/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.theme;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

/**
 * Completes a merged theme's palette (Task 3 UI/UX review B1): every missing dark value is derived
 * ({@link DarkPalette}), and when the theme brings its own palette, the supporting roles it leaves unset — border,
 * focus ring, the three tints and the sunken surface — are derived from ITS colours instead of keeping HelixIAM's
 * cream-and-sage defaults. A role "left unset" is one that still holds exactly the HelixIAM default (a layer that
 * sets a colour replaces the whole colour, so an untouched role is identical to the default).
 *
 * <ul>
 *   <li>{@code border} = 12 % ink in surface (light), 16 % in dark;</li>
 *   <li>{@code focusRing} = {@code primary} (≥ 3:1 on the surfaces for any valid theme);</li>
 *   <li>{@code primaryTint}/{@code negativeTint}/{@code positiveTint} = 12 % of the colour in surfaceRaised
 *       (18 % in dark);</li>
 *   <li>{@code surfaceSunken} = 4 % ink in surface (light), surface darkened by 30 % (dark).</li>
 * </ul>
 */
public final class ThemePalette {

    /** Roles derived from the theme's own colours when it leaves them unset. */
    public static final Set<String> DERIVED = Set.of("border", "focusRing", "primaryTint", "negativeTint",
            "positiveTint", "surfaceSunken");

    private ThemePalette() {
    }

    /** {@code merged} (all layers, HelixIAM default at the bottom) with a complete, theme-consistent palette. */
    public static Theme resolve(final Theme merged) {
        final Theme resolved = DarkPalette.resolve(merged);
        final ThemeColors c = resolved.colors();
        if (!ownPalette(c)) {
            return resolved;
        }
        final Map<String, ThemeColor> out = new LinkedHashMap<>();
        for (final String role : ThemeColors.ROLES) {
            final ThemeColor current = c.role(role);
            out.put(role, DERIVED.contains(role) && isDefault(role, current) ? derive(role, c) : current);
        }
        return resolved.withColors(ThemeColors.from(out::get));
    }

    private static boolean ownPalette(final ThemeColors c) {
        for (final String role : ThemeColors.ROLES) {
            if (!DERIVED.contains(role) && !isDefault(role, c.role(role))) {
                return true;
            }
        }
        return false;
    }

    private static boolean isDefault(final String role, final ThemeColor color) {
        final ThemeColor d = ThemeDefaults.THEME.colors().role(role);
        return color != null && d.light().equalsIgnoreCase(color.light()) && d.dark().equalsIgnoreCase(color.dark());
    }

    private static ThemeColor derive(final String role, final ThemeColors c) {
        return switch (role) {
            case "border" -> new ThemeColor(mix(c.ink().light(), c.surface().light(), 0.12),
                    mix(c.ink().dark(), c.surface().dark(), 0.16));
            case "focusRing" -> c.primary();
            case "primaryTint" -> tint(c.primary(), c.surfaceRaised());
            case "negativeTint" -> tint(c.negative(), c.surfaceRaised());
            case "positiveTint" -> tint(c.positive(), c.surfaceRaised());
            case "surfaceSunken" -> new ThemeColor(mix(c.ink().light(), c.surface().light(), 0.04),
                    mix("#000000", c.surface().dark(), 0.30));
            default -> throw new IllegalArgumentException(role);
        };
    }

    private static ThemeColor tint(final ThemeColor color, final ThemeColor raised) {
        return new ThemeColor(mix(color.light(), raised.light(), 0.12), mix(color.dark(), raised.dark(), 0.18));
    }

    private static String mix(final String a, final String b, final double weightA) {
        return ThemeColorMath.mix(a, b, weightA);
    }
}
