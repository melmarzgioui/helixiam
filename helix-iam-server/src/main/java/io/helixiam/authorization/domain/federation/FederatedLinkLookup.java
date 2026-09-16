/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.domain.federation;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/**
 * Helix IAM E5.3: AMQP request DTO — resolve the local user previously linked to an external
 * identity. Two-copy mirror of the publisher's DTO.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record FederatedLinkLookup(String idpAlias, String externalSubject) {
}
