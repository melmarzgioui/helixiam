/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.theme;

import com.fasterxml.jackson.annotation.JsonInclude;

import java.util.List;

/**
 * Page layout: {@code split} (brand panel and form) or {@code centered} (form only); whether the language switcher
 * shows; and the locales offered (a single entry hides the switcher).
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record ThemeLayout(String layout, Boolean showLanguageSwitcher, List<String> supportedLocales) {
}
