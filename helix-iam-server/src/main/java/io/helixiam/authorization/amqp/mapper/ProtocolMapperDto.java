/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.amqp.mapper;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/**
 * Helix IAM (parity Wave 3): a per-client protocol mapper (publisher copy). Maps a {@code source}
 * (a user-profile attribute key, or a hardcoded value) into {@code claimName} in the access and/or ID token.
 * {@code mapperType} is {@code USER_ATTRIBUTE} or {@code HARDCODED}.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record ProtocolMapperDto(String mapperId, String realmId, String clientId, String name, String mapperType,
                                String source, String claimName, boolean addToAccessToken, boolean addToIdToken) {
}
