/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.amqp.org;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/**
 * Open issue E5: the outcome of putting a membership — the member as stored and whether it was added
 * ({@code created}) or changed in place.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record OrgMemberChange(boolean created, OrgMemberDto member) {
}
