/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.theme;

import com.fasterxml.jackson.annotation.JsonInclude;

/** The theme's colour roles (spec §1). Every role is optional in a stored layer; null means "inherit". */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record ThemeColors(ThemeColor primary, ThemeColor primaryStrong, ThemeColor primaryTint,
                          ThemeColor surface, ThemeColor surfaceRaised, ThemeColor surfaceSunken,
                          ThemeColor ink, ThemeColor inkMuted, ThemeColor border,
                          ThemeColor negative, ThemeColor negativeTint, ThemeColor positive, ThemeColor positiveTint,
                          ThemeColor focusRing) {

    /** Role names in declaration order — also the JSON property names. */
    public static final java.util.List<String> ROLES = java.util.List.of("primary", "primaryStrong", "primaryTint",
            "surface", "surfaceRaised", "surfaceSunken", "ink", "inkMuted", "border",
            "negative", "negativeTint", "positive", "positiveTint", "focusRing");

    /** The colour for a role name from {@link #ROLES}. */
    public ThemeColor role(final String name) {
        return switch (name) {
            case "primary" -> primary;
            case "primaryStrong" -> primaryStrong;
            case "primaryTint" -> primaryTint;
            case "surface" -> surface;
            case "surfaceRaised" -> surfaceRaised;
            case "surfaceSunken" -> surfaceSunken;
            case "ink" -> ink;
            case "inkMuted" -> inkMuted;
            case "border" -> border;
            case "negative" -> negative;
            case "negativeTint" -> negativeTint;
            case "positive" -> positive;
            case "positiveTint" -> positiveTint;
            case "focusRing" -> focusRing;
            default -> throw new IllegalArgumentException("Unknown colour role " + name);
        };
    }

    /** Builds a {@link ThemeColors} from a role lookup (the inverse of {@link #role}). */
    public static ThemeColors from(final java.util.function.Function<String, ThemeColor> lookup) {
        return new ThemeColors(lookup.apply("primary"), lookup.apply("primaryStrong"), lookup.apply("primaryTint"),
                lookup.apply("surface"), lookup.apply("surfaceRaised"), lookup.apply("surfaceSunken"),
                lookup.apply("ink"), lookup.apply("inkMuted"), lookup.apply("border"),
                lookup.apply("negative"), lookup.apply("negativeTint"), lookup.apply("positive"),
                lookup.apply("positiveTint"), lookup.apply("focusRing"));
    }
}
