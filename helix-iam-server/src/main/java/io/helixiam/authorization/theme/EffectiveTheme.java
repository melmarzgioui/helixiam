/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.theme;

import java.util.Set;

/**
 * The fully resolved theme for a realm (and optionally an organization): every layer merged, every dark value
 * present, stored custom CSS re-validated. {@code version} is the SHA-256 of its canonical JSON — stable while the
 * theme is unchanged, so {@code theme.css} can use it as a strong ETag. {@code imageOrigins} are the https origins
 * images may load from (configured allowlist plus the theme's own asset URLs) — the per-realm {@code img-src}.
 */
public record EffectiveTheme(Theme theme, String version, Set<String> imageOrigins) {
}
