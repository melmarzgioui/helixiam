/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.domain.theme;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

import java.time.Instant;

/**
 * An organization's stored theme layer ({@code organization_theme}), applied over its realm's theme when the
 * organization is in context. Carries the realm id so every lookup can be scoped to the path realm.
 */
@Entity
@Table(name = "organization_theme")
public class OrganizationThemeRecord {

    @Id
    @Column(name = "org_id")
    private String orgId;

    @Column(name = "realm_id", nullable = false)
    private String realmId;

    @Column(name = "theme_json", nullable = false, columnDefinition = "text")
    private String themeJson;

    @Column(name = "updated_at")
    private Instant updatedAt;

    protected OrganizationThemeRecord() {
    }

    public OrganizationThemeRecord(final String orgId, final String realmId, final String themeJson) {
        this.orgId = orgId;
        this.realmId = realmId;
        this.themeJson = themeJson;
        this.updatedAt = Instant.now();
    }

    public String getOrgId() {
        return orgId;
    }

    public String getRealmId() {
        return realmId;
    }

    public String getThemeJson() {
        return themeJson;
    }

    public void setThemeJson(final String themeJson) {
        this.themeJson = themeJson;
        this.updatedAt = Instant.now();
    }

    public Instant getUpdatedAt() {
        return updatedAt;
    }
}
