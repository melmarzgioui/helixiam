/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.amqp.client;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/** Helix IAM E8.5-S3: references a single OAuth client (publisher-side copy). */
@JsonIgnoreProperties(ignoreUnknown = true)
public record ClientRef(String realmId, String id) {
}
