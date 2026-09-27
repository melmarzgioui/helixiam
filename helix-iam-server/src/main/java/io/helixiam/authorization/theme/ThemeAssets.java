/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.theme;

import com.fasterxml.jackson.annotation.JsonInclude;

/**
 * Images: each an absolute {@code https} URL or one of the realm's own uploaded assets
 * ({@code /realms/{realm}/theme/assets/{id}.{ext}}).
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record ThemeAssets(String logoUrl, String logoDarkUrl, String faviconUrl, String brandImageUrl) {
}
