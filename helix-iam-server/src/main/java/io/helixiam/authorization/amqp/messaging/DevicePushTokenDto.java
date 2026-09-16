/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.amqp.messaging;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/** Helix IAM notifications (N6c): a registered push device token (publisher copy). */
@JsonIgnoreProperties(ignoreUnknown = true)
public record DevicePushTokenDto(String realmId, String userId, String platform, String token) {
}
