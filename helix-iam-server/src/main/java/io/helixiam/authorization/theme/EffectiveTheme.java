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
 * @param customized    true when any layer above the built-in HelixIAM default sets something (a file theme, the
 *                      realm's or the organization's theme): the page is then the customer's brand, never HelixIAM's
 */
public record EffectiveTheme(Theme theme, String version, Set<String> imageOrigins, Set<String> cssUrlOrigins,
                             boolean customized) {

    /** The built-in look (nothing customised). */
    public EffectiveTheme(final Theme theme, final String version, final Set<String> imageOrigins,
                          final Set<String> cssUrlOrigins) {
        this(theme, version, imageOrigins, cssUrlOrigins, false);
    }
}
