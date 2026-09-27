/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.domain.org.admin;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.util.List;

/** Helix IAM Organizations: create/update payload for an organization (mirrors the publisher copy). */
@JsonIgnoreProperties(ignoreUnknown = true)
public record OrgWriteDto(String realmId, String orgId, String name, String displayName, List<String> domains,
                          boolean enabled, Boolean requireMembership) {

    /** Without {@code requireMembership} (item E4): unchanged on update, off on create. */
    public OrgWriteDto(final String realmId, final String orgId, final String name, final String displayName,
                       final List<String> domains, final boolean enabled) {
        this(realmId, orgId, name, displayName, domains, enabled, null);
    }
}
