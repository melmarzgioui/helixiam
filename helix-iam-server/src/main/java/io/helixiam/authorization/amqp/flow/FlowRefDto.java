/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.amqp.flow;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/** Helix IAM (named flows): a reference to one realm flow by alias (get / delete). Mirrors the publisher copy. */
@JsonIgnoreProperties(ignoreUnknown = true)
public record FlowRefDto(String realmId, String alias) {
}
