/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.domain.messaging.admin;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/** Helix IAM notifications (N1): identifies one provider for get/delete — realm + channel + driver. */
@JsonIgnoreProperties(ignoreUnknown = true)
public record MessagingProviderKey(String realmId, String channel, String driver) {
}
