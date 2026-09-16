/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.amqp.org;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.util.List;

/**
 * Helix IAM Organizations: a user's membership in one organization, shaped for token enrichment — the
 * {@code organizations} claim is an array of these (mirrors the subscriber copy).
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record OrgMembershipDto(String id, String name, List<String> roles) {
}
