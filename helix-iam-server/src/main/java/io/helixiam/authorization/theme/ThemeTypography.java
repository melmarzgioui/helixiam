/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.theme;

import com.fasterxml.jackson.annotation.JsonInclude;

/**
 * Fonts and base size. {@code fontSans} / {@code fontDisplay} are a built-in stack name ({@code system-sans},
 * {@code system-serif}, {@code system-mono}) or the name of a font uploaded to the realm (resolved through
 * {@link ThemeAssetCatalog}). {@code baseSize} is in px, 14–18.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record ThemeTypography(String fontSans, String fontDisplay, Integer baseSize) {
}
