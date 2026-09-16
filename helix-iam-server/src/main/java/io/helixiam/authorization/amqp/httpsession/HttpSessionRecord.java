/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.amqp.httpsession;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/** Helix IAM (Q3): the wire form of a stored HTTP session (publisher copy). */
@JsonIgnoreProperties(ignoreUnknown = true)
public record HttpSessionRecord(String sessionId, String principalName, String blob, Long creationTime,
                                Long lastAccessTime, Integer maxInactiveSeconds, Long expiryTime) {
}
