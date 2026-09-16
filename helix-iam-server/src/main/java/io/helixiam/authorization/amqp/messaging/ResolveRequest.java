/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.amqp.messaging;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/** Helix IAM notifications (N3): resolve the enabled providers for (realm, channel) on the sender path. */
@JsonIgnoreProperties(ignoreUnknown = true)
public record ResolveRequest(String realmId, String channel) {
}
