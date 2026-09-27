/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.theme.asset;

import com.fasterxml.jackson.annotation.JsonValue;

import java.util.Locale;

/** What an uploaded theme asset is: a font (woff2) or an image (svg, png, webp). */
public enum ThemeAssetKind {
    FONT,
    IMAGE;

    /** The stored and JSON form ({@code font}, {@code image}). */
    @JsonValue
    public String key() {
        return name().toLowerCase(Locale.ROOT);
    }

    /** Parses {@link #key()}. */
    public static ThemeAssetKind fromKey(final String key) {
        return valueOf(key.toUpperCase(Locale.ROOT));
    }
}
