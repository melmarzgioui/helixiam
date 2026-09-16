/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.amqp.messaging;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/** Helix IAM notifications (N2): identifies one provider for delete — realm + channel + driver. */
@JsonIgnoreProperties(ignoreUnknown = true)
public record MessagingProviderKey(String realmId, String channel, String driver) {
}
