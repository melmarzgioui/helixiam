/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.controller.account;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import jakarta.validation.constraints.Email;

import java.util.Map;

/**
 * Helix IAM (6) Self-service Account: the body a signed-in user PUTs to update <em>their own</em> profile.
 * Username is intentionally absent — it is read-only and always taken from the authenticated principal, so a
 * user can never rename themselves (or anyone else) through this surface. Only email + attributes are editable.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record AccountProfileRequest(@Email(message = "Email must be a valid address.") String email,
                                    Map<String, String> attributes) {
}
