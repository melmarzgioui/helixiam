/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.amqp.mapper;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/**
 * Helix IAM (Wave 3): references one protocol mapper of a client (publisher copy). {@code mapperId} is null
 * when the request addresses the client as a whole (e.g. list).
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record MapperRef(String realmId, String clientId, String mapperId) {
}
