/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.domain.user.admin;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.util.List;
import java.util.Map;

/**
 * Helix IAM E8.5: subscriber-side view of a realm user for the admin console (two-copy DTO; mirrors
 * the publisher's {@code amqp.user.UserAdminDto}). Read-only projection assembled from the global
 * {@code user_credentials} row plus the realm's {@code tenant_user} link and its role assignments.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record UserAdminDto(String realmId, String userId, String username, String email, boolean enabled,
                           boolean locked, boolean mfaEnabled, List<String> roles, Map<String, String> attributes,
                           Long createdAt, boolean emailVerified, boolean emailBounced, Long emailBouncedAt) {

    /**
     * Without the bounce state: {@code emailBounced} is true while mail to the user's current address bounced
     * permanently, {@code emailBouncedAt} is when (epoch millis); both clear when the address changes or is verified.
     */
    public UserAdminDto(final String realmId, final String userId, final String username, final String email,
                        final boolean enabled, final boolean locked, final boolean mfaEnabled, final List<String> roles,
                        final Map<String, String> attributes, final Long createdAt, final boolean emailVerified) {
        this(realmId, userId, username, email, enabled, locked, mfaEnabled, roles, attributes, createdAt, emailVerified,
                false, null);
    }

    /** C3: without {@code emailVerified} (false). */
    public UserAdminDto(final String realmId, final String userId, final String username, final String email,
                        final boolean enabled, final boolean locked, final boolean mfaEnabled, final List<String> roles,
                        final Map<String, String> attributes, final Long createdAt) {
        this(realmId, userId, username, email, enabled, locked, mfaEnabled, roles, attributes, createdAt, false);
    }
}
