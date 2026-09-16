/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.amqp.clientrole;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/** Helix IAM (Wave 4): references a client (and optionally one of its roles by {@code name}). Publisher copy. */
@JsonIgnoreProperties(ignoreUnknown = true)
public record ClientRoleRef(String realmId, String clientId, String name) {
}
