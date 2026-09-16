/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.domain.messaging.admin;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.util.Map;

/**
 * Helix IAM notifications (N1): subscriber-side read view of a messaging provider. {@code config} is the
 * non-secret driver settings; the secret itself is never returned — {@code secretSet} only reports whether
 * one is stored (mirrors how client secrets are masked on read).
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record MessagingProviderDto(String id, String realmId, String channel, String driver, boolean enabled,
                                   String fromAddress, String fromName, Map<String, String> config, boolean secretSet) {
}
