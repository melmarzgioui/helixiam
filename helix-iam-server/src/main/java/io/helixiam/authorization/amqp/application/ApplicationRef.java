/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.amqp.application;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/**
 * Helix IAM: a (realm, name) reference for fetch/delete of an Application.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record ApplicationRef(String realmId, String name) {
}
