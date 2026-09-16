/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.amqp.gdpr;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/** Helix IAM GDPR Art. 7: withdraw a user's consent for one client (publisher-side copy). */
@JsonIgnoreProperties(ignoreUnknown = true)
public record GdprConsentWithdrawDto(String realmId, String userId, String clientId) {
}
