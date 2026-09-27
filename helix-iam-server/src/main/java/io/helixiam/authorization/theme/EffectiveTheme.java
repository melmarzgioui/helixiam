/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.theme;

import java.util.Set;

/**
 * The fully resolved theme for a realm (and optionally an organization): every layer merged, every dark value
 * present, stored custom CSS re-validated. {@code version} is the SHA-256 of its canonical JSON — stable while the
 * theme is unchanged, so {@code theme.css} can use it as a strong ETag.
 *
 * @param imageOrigins  the https origins images may load from — the operator allowlist plus the origins of the
 *                      theme's own image URLs (logo, favicon, …): the per-realm {@code img-src}
 * @param cssUrlOrigins the https origins custom CSS {@code url()} may fetch from — the operator allowlist ONLY
 *                      ({@code helix.theme.allowed-image-origins}); theme asset URLs never widen it
 */
public record EffectiveTheme(Theme theme, String version, Set<String> imageOrigins, Set<String> cssUrlOrigins) {
}
