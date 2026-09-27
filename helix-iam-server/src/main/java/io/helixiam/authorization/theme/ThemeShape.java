/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.theme;

import com.fasterxml.jackson.annotation.JsonInclude;

/** Corner radius in px (0–16) and density ({@code comfortable} or {@code compact}). */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record ThemeShape(Integer radius, String density) {
}
