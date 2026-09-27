/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.theme;

import com.fasterxml.jackson.annotation.JsonInclude;

/**
 * Plain-text brand copy, localised per locale ({@link LocalizedText}); rendered escaped. A missing text falls back
 * to the built-in messages. {@code brandBadges}: an empty list hides the badges, null inherits.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record ThemeTexts(LocalizedText brandHeadline, LocalizedText brandSubhead, LocalizedText brandByline,
                         LocalizedText welcomeText, LocalizedText footerText, LocalizedList brandBadges) {
}
