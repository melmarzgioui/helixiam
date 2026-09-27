/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.controller.admin;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

/**
 * C2: body of {@code POST /admin/realms/{r}/clients/{id}/secret}. With {@code secret} set, that value becomes the
 * client's secret (write-only, never returned); without it the server generates a new one and returns it once.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record ClientSecretRequest(@Size(min = MIN_LENGTH, max = MAX_LENGTH, message = LENGTH_MESSAGE)
                                  @Pattern(regexp = PATTERN, message = LENGTH_MESSAGE) String secret) {

    /** Minimum length of a caller-supplied client secret. */
    public static final int MIN_LENGTH = 32;
    /** Upper bound, so the AES-GCM-encrypted, Base64-encoded secret always fits the {@code varchar(200)} column. */
    public static final int MAX_LENGTH = 120;
    /** Printable ASCII without spaces: safe in {@code client_secret_basic} and {@code client_secret_post}. */
    public static final String PATTERN = "^[\\x21-\\x7E]*$";
    public static final String LENGTH_MESSAGE =
            "The client secret must be 32 to 120 printable ASCII characters without spaces.";

    /** Never print the secret. */
    @Override
    public String toString() {
        return "ClientSecretRequest[secret=" + (secret == null ? "null" : "***") + "]";
    }
}
