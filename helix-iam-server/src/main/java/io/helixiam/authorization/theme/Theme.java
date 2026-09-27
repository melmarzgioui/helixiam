/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.theme;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;

/**
 * A structured theme (spec §1): colours, typography, shape, assets, layout, texts, links and the restricted
 * custom-CSS escape hatch (spec §4). Never raw CSS apart from {@code customCss}, which is validated by
 * {@link CustomCssValidator}.
 *
 * <p>The same shape is used for every layer — the HelixIAM default ({@link ThemeDefaults}), a base layer (for
 * example a file theme, see {@link BaseThemeProvider}), the realm theme and the organization theme. In a stored
 * layer every field is optional and {@code null} means "inherit from the layer below"; {@link ThemeMerger} merges
 * the layers field by field and {@link ThemeService#effectiveTheme} returns the fully resolved result.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(value = {"notices"}, ignoreUnknown = true)
public record Theme(ThemeColors colors, ThemeTypography typography, ThemeShape shape, ThemeAssets assets,
                    ThemeLayout layout, ThemeTexts texts, ThemeLinks links, String customCss) {

    /** A layer that sets nothing (inherits everything). */
    public static final Theme EMPTY = new Theme(null, null, null, null, null, null, null, null);

    /** True when the layer sets nothing. */
    @JsonIgnore
    public boolean isEmpty() {
        return ThemeJson.write(this).equals(ThemeJson.write(EMPTY));
    }

    public Theme withColors(final ThemeColors value) {
        return new Theme(value, typography, shape, assets, layout, texts, links, customCss);
    }

    public Theme withAssets(final ThemeAssets value) {
        return new Theme(colors, typography, shape, value, layout, texts, links, customCss);
    }

    public Theme withTexts(final ThemeTexts value) {
        return new Theme(colors, typography, shape, assets, layout, value, links, customCss);
    }

    public Theme withCustomCss(final String value) {
        return new Theme(colors, typography, shape, assets, layout, texts, links, value);
    }
}
