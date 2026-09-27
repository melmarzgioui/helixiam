/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.theme;

import com.fasterxml.jackson.annotation.JsonInclude;

/**
 * One theme colour: a {@code #RRGGBB} value for the light scheme and, optionally, for the dark scheme. A missing
 * {@code dark} value is derived from {@code light} when the effective theme is resolved ({@link DarkPalette}).
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record ThemeColor(String light, String dark) {

    /** A colour with only a light value (the dark one is derived). */
    public static ThemeColor of(final String light) {
        return new ThemeColor(light, null);
    }
}
