/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.domain.org;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

import java.util.UUID;

/**
 * Helix IAM Organizations: a B2B tenant grouping of users within a realm (Keycloak Organizations /
 * WorkOS-class). Has a stable {@code name} (unique per realm), a human {@code displayName}, and one or
 * more email {@code domains} (comma-joined) used for domain-based membership. Realm-scoped via
 * {@code tenant_id}; flat columns. Members live in {@link OrganizationMember}.
 */
@Entity
@Table(name = "organization")
public class Organization {

    @Id
    @Column(name = "org_id")
    private String orgId;

    @Column(name = "tenant_id")
    private String tenantId;

    @Column(name = "name")
    private String name;

    @Column(name = "display_name")
    private String displayName;

    /** Comma-separated email domains (e.g. {@code "acme.com,acme.io"}); never null in practice. */
    @Column(name = "domains")
    private String domains;

    @Column(name = "enabled")
    private boolean enabled = true;

    public Organization() {
    }

    public Organization(final String tenantId, final String name, final String displayName,
                        final String domains, final boolean enabled) {
        this.orgId = UUID.randomUUID().toString();
        this.tenantId = tenantId;
        this.name = name;
        this.displayName = displayName;
        this.domains = domains;
        this.enabled = enabled;
    }

    public String getOrgId() {
        return orgId;
    }

    public void setOrgId(final String orgId) {
        this.orgId = orgId;
    }

    public String getTenantId() {
        return tenantId;
    }

    public void setTenantId(final String tenantId) {
        this.tenantId = tenantId;
    }

    public String getName() {
        return name;
    }

    public void setName(final String name) {
        this.name = name;
    }

    public String getDisplayName() {
        return displayName;
    }

    public void setDisplayName(final String displayName) {
        this.displayName = displayName;
    }

    public String getDomains() {
        return domains;
    }

    public void setDomains(final String domains) {
        this.domains = domains;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(final boolean enabled) {
        this.enabled = enabled;
    }
}
