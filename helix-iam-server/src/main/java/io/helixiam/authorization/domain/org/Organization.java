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

    /** Item E4: when hinted on a sign-in, only members may complete it (else access_denied to the client). */
    @Column(name = "require_membership")
    private boolean requireMembership = false;

    /**
     * 1.0 item 7 (legacy column): since structured theming (Flyway V20) the logo and primary colour live on the
     * organization theme ({@code organization_theme}): Flyway V20 / the backfill move them there and set these columns
     * to NULL. They stay in the schema but are no longer read or written; a rollback to 1.0 finds them empty.
     */
    @Column(name = "logo_url")
    private String logoUrl;

    /** 1.0 item 7: primary colour as #RRGGBB. */
    @Column(name = "primary_color")
    private String primaryColor;

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

    public boolean isRequireMembership() {
        return requireMembership;
    }

    public void setRequireMembership(final boolean requireMembership) {
        this.requireMembership = requireMembership;
    }

    public String getLogoUrl() {
        return logoUrl;
    }

    public void setLogoUrl(final String logoUrl) {
        this.logoUrl = logoUrl;
    }

    public String getPrimaryColor() {
        return primaryColor;
    }

    public void setPrimaryColor(final String primaryColor) {
        this.primaryColor = primaryColor;
    }
}
