/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.amqp.resource;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.util.List;

/**
 * Helix IAM (RFC 8707): admin write payload to set a client's allowed-resource allow-list (publisher-side
 * copy; mirrors the subscriber's {@code domain.resource.AllowedResourcesWrite}). The client is identified
 * by {@code clientId} <b>within {@code realmId}</b>. Empty/null {@code resources} clears the allow-list.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record AllowedResourcesWrite(String realmId, String clientId, List<String> resources) {
}
