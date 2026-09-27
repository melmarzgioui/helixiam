/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.amqp.user;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.util.Map;

/** Helix IAM E8.5: create/update payload for a realm user (publisher-side copy). */
@JsonIgnoreProperties(ignoreUnknown = true)
public record UserWriteDto(String realmId, String userId, String username, String email, String password,
                           boolean enabled, boolean locked, Map<String, String> attributes, Boolean emailVerified) {

    /** C3: without {@code emailVerified} (null = unchanged on update, unverified on create). */
    public UserWriteDto(final String realmId, final String userId, final String username, final String email,
                        final String password, final boolean enabled, final boolean locked,
                        final Map<String, String> attributes) {
        this(realmId, userId, username, email, password, enabled, locked, attributes, null);
    }
}
