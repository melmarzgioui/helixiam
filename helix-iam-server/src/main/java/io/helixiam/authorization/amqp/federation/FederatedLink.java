/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.amqp.federation;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/**
 * Helix IAM E5.3: AMQP request DTO — record a federated link from an external subject (at the given
 * provider) to a local user. JSON-marshalled, two-copy on each side.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record FederatedLink(String idpAlias, String externalSubject, String userId) {
}
