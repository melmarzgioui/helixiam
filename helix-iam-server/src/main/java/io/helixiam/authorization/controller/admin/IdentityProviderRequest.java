/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.controller.admin;

import jakarta.validation.constraints.NotBlank;

import java.util.Map;

/**
 * Helix IAM E8.2: request body for creating/updating an identity-provider connection. The realm and
 * (on update) the alias come from the path — never the body — so a connection cannot be written into
 * another realm or silently re-aliased.
 */
public record IdentityProviderRequest(@NotBlank(message = "Provider alias is required.") String alias,
                                      @NotBlank(message = "Provider protocol is required.") String protocol,
                                      String displayName, boolean enabled,
                                      Map<String, String> config) {
}
