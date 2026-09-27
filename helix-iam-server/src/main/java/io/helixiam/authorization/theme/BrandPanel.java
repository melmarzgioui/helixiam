/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.theme;

/**
 * The colours of the split layout's brand panel, derived from the palette (the model has no panel field). The one
 * place both {@code theme.css} and the validator read them from.
 *
 * <ul>
 *   <li>Light scheme: the panel inverts the page — ground {@code ink}, text {@code surface}, accent
 *       {@code primary}'s dark value (lightness nudged to AA on the ground when needed, like derived dark values).</li>
 *   <li>Dark scheme: ground = 14 % of the dark primary in the dark sunken surface (so it stands apart from the dark
 *       form side), text {@code ink}, accent {@code primary}'s dark value.</li>
 * </ul>
 */
public final class BrandPanel {

    /** Ground, text and accent of the panel in one scheme. */
    public record Colors(String background, String foreground, String accent) {
    }

    private BrandPanel() {
    }

    /** The light-scheme panel of a resolved palette. */
    public static Colors light(final ThemeColors c) {
        return new Colors(c.ink().light(), c.surface().light(),
                ThemeColorMath.ensureContrast(c.primary().dark(), c.ink().light(), ThemeColorMath.AA_TEXT));
    }

    /** The dark-scheme panel of a resolved palette. */
    public static Colors dark(final ThemeColors c) {
        final String ground = ThemeColorMath.mix(c.primary().dark(), c.surfaceSunken().dark(), 0.14);
        return new Colors(ground, c.ink().dark(),
                ThemeColorMath.ensureContrast(c.primary().dark(), ground, ThemeColorMath.AA_TEXT));
    }
}
