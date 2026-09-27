/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.theme;

import com.fasterxml.jackson.annotation.JsonInclude;

/** Legal and support links shown on the pages; {@code https} only. */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record ThemeLinks(String privacyUrl, String termsUrl, String supportUrl) {
}
