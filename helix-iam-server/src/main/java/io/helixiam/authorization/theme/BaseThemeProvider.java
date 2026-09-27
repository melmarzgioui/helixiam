/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.theme;

import java.util.Optional;

/**
 * Hook for base theme layers between the HelixIAM default and a realm's database theme (plan Task 5: file themes
 * mounted from {@code helix.theme.directory}). Every Spring bean implementing this is applied in {@code @Order},
 * above {@link ThemeDefaults#THEME} and below the realm theme, so database fields override file values.
 *
 * <p>An implementation must only return layers that passed {@link ThemeValidator} (a failing theme is refused and
 * logged, and the realm falls back to its database theme or the default).
 */
public interface BaseThemeProvider {

    /** The base layer for {@code realmId}, or empty when this provider has none. */
    Optional<Theme> baseTheme(String realmId);
}
