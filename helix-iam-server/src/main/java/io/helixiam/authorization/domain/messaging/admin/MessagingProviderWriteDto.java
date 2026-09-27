/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.domain.messaging.admin;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.util.Map;

/**
 * Helix IAM notifications (N1): create/update payload for a messaging provider. {@code secret} is
 * write-only — {@code null}/blank keeps the stored secret, a value replaces it.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record MessagingProviderWriteDto(String realmId, String channel, String driver, boolean enabled,
                                        String fromAddress, String fromName, Map<String, String> config,
                                        String secret,
                                        Boolean clearSecret) {

    /**
     * {@code secret}: write-only. Absent, null or blank keeps the stored secret; a value replaces it.
     * {@code clearSecret}: {@code true} removes the stored secret (the provider stays); it cannot be combined with a
     * new {@code secret}. Without it the secret is never removed.
     */
    public MessagingProviderWriteDto(final String realmId, final String channel, final String driver,
                                     final boolean enabled, final String fromAddress, final String fromName,
                                     final Map<String, String> config, final String secret) {
        this(realmId, channel, driver, enabled, fromAddress, fromName, config, secret, null);
    }

    /** True when the stored secret is to be removed. */
    public boolean clearsSecret() {
        return Boolean.TRUE.equals(clearSecret);
    }
}
