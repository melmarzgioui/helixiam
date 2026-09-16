/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.amqp.gdpr;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/**
 * Helix IAM GDPR: identifies the data subject an Art. 15/17/20 request is about (publisher-side copy;
 * mirrors the subscriber's {@code domain.gdpr.GdprUserRef}).
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record GdprUserRef(String realmId, String userId) {
}
