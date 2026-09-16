/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.domain.messaging.admin;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.util.Map;

/**
 * Helix IAM notifications (N3): a resolved provider for the SENDER path — carries the decrypted {@code secret}
 * so a driver can authenticate. Server-to-server only (publisher sender ← subscriber); NEVER exposed by the
 * admin REST API (that path uses {@link MessagingProviderDto} with the secret masked).
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record ResolvedProviderDto(String channel, String driver, String fromAddress, String fromName,
                                  Map<String, String> config, String secret) {
}
