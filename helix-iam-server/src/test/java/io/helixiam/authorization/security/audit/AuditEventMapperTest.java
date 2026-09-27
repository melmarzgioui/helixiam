/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.security.audit;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Helix IAM E8.5-S4 (Events): the pure mapping from an admin HTTP request to an audit descriptor.
 */
class AuditEventMapperTest {

    private AuditEventMapper.AdminAudit map(final String method, final String path, final int status) {
        return AuditEventMapper.map(method, path, status);
    }

    @Test
    void mapsUserLifecycle() {
        assertEquals("USER_CREATE", map("POST", "/admin/realms/gov/users", 201).type());
        assertEquals("USER_UPDATE", map("PUT", "/admin/realms/gov/users/u-1", 200).type());
        assertEquals("USER_DELETE", map("DELETE", "/admin/realms/gov/users/u-1", 204).type());

        final AuditEventMapper.AdminAudit u = map("DELETE", "/admin/realms/gov/users/u-1", 204);
        assertEquals("gov", u.realm());
        assertEquals("user", u.resourceType());
        assertEquals("u-1", u.resourceId());
        assertEquals("SUCCESS", u.outcome());
    }

    @Test
    void mapsPasswordResetAndUserRoleAssignment() {
        assertEquals("PASSWORD_RESET", map("PUT", "/admin/realms/gov/users/u-1/password", 204).type());
        assertEquals("ROLE_ASSIGN", map("PUT", "/admin/realms/gov/users/u-1/roles/r-1", 204).type());
        assertEquals("ROLE_UNASSIGN", map("DELETE", "/admin/realms/gov/users/u-1/roles/r-1", 204).type());
    }

    @Test
    void mapsRolesClientsRealmSessionsFlow() {
        assertEquals("ROLE_CREATE", map("POST", "/admin/realms/gov/roles", 201).type());
        assertEquals("ROLE_DELETE", map("DELETE", "/admin/realms/gov/roles/r-1", 204).type());

        assertEquals("CLIENT_CREATE", map("POST", "/admin/realms/gov/clients", 201).type());
        assertEquals("CLIENT_UPDATE", map("PUT", "/admin/realms/gov/clients/c-1", 200).type());
        assertEquals("CLIENT_DELETE", map("DELETE", "/admin/realms/gov/clients/c-1", 204).type());
        final AuditEventMapper.AdminAudit secret = map("POST", "/admin/realms/gov/clients/c-1/secret", 200);
        assertEquals("CLIENT_SECRET_ROTATE", secret.type());
        assertEquals("client", secret.resourceType());
        assertEquals("c-1", secret.resourceId());

        assertEquals("REALM_UPDATE", map("PUT", "/admin/realms/gov/settings", 200).type());
        assertEquals("SESSION_REVOKE", map("DELETE", "/admin/realms/gov/sessions/s-1", 204).type());
        assertEquals("FLOW_UPDATE", map("PUT", "/admin/realms/gov/flow", 200).type());
    }

    @Test
    void mapsGroupLifecycleMembersAndRoles() {
        assertEquals("GROUP_CREATE", map("POST", "/admin/realms/gov/groups", 201).type());
        assertEquals("GROUP_UPDATE", map("PUT", "/admin/realms/gov/groups/g-1", 200).type());
        assertEquals("GROUP_DELETE", map("DELETE", "/admin/realms/gov/groups/g-1", 204).type());
        assertEquals("GROUP_MEMBER_ADD", map("PUT", "/admin/realms/gov/groups/g-1/members/u-1", 204).type());
        assertEquals("GROUP_MEMBER_REMOVE", map("DELETE", "/admin/realms/gov/groups/g-1/members/u-1", 204).type());
        assertEquals("GROUP_ROLE_ASSIGN", map("PUT", "/admin/realms/gov/groups/g-1/roles/r-1", 204).type());
        assertEquals("GROUP_ROLE_UNASSIGN", map("DELETE", "/admin/realms/gov/groups/g-1/roles/r-1", 204).type());

        final AuditEventMapper.AdminAudit g = map("PUT", "/admin/realms/gov/groups/g-1/members/u-1", 204);
        assertEquals("group", g.resourceType());
        assertEquals("g-1", g.resourceId());
    }

    @Test
    void mapsOrganizationMembershipChanges() {
        assertEquals("ORGANIZATION_MEMBER_PUT", map("PUT", "/admin/realms/gov/organizations/o-1/members/u-1", 200).type());
        assertEquals("ORGANIZATION_MEMBER_PUT", map("PUT", "/admin/realms/gov/organizations/o-1/members/u-1", 201).type());
        assertEquals("ORGANIZATION_MEMBER_REMOVE",
                map("DELETE", "/admin/realms/gov/organizations/o-1/members/u-1", 204).type());
        final AuditEventMapper.AdminAudit m = map("PUT", "/admin/realms/gov/organizations/o-1/members/u-1", 200);
        assertEquals("organizations", m.resourceType());
        assertEquals("o-1", m.resourceId());
    }

    @Test
    void deniedAndFailureOutcomesFromStatus() {
        assertEquals("DENIED", map("DELETE", "/admin/realms/gov/sessions/missing", 404).outcome());
        assertEquals("DENIED", map("POST", "/admin/realms/gov/users", 403).outcome());
        assertEquals("FAILURE", map("POST", "/admin/realms/gov/users", 500).outcome());
    }

    @Test
    void unmappedMutatingRouteFallsBackToGenericAdminType() {
        final AuditEventMapper.AdminAudit a = map("POST", "/admin/realms/gov/widgets/w-1", 200);
        assertEquals("ADMIN_POST", a.type());
        assertEquals("widgets", a.resourceType());
        assertEquals("w-1", a.resourceId());
    }

    @Test
    void mapsThemeUpdates() {
        final AuditEventMapper.AdminAudit realm = map("PUT", "/admin/realms/gov/theme", 200);
        assertEquals("THEME_UPDATE", realm.type());
        assertEquals("theme", realm.resourceType());
        final AuditEventMapper.AdminAudit org = map("PUT", "/admin/realms/gov/organizations/o-1/theme", 200);
        assertEquals("ORGANIZATION_THEME_UPDATE", org.type());
        assertEquals("o-1", org.resourceId());
        assertEquals("ORGANIZATION_THEME_UPDATE", map("PUT", "/admin/realms/gov/organizations/o-1/branding", 200).type());
    }

    @Test
    void mapsThemeAssetUploadsAndDeletions() {
        final AuditEventMapper.AdminAudit upload = map("POST", "/admin/realms/gov/theme/assets", 201);
        assertEquals("THEME_ASSET_UPLOAD", upload.type());
        assertEquals("theme-asset", upload.resourceType());
        assertEquals("gov", upload.realm());
        final AuditEventMapper.AdminAudit delete = map("DELETE", "/admin/realms/gov/theme/assets/a-1", 409);
        assertEquals("THEME_ASSET_DELETE", delete.type());
        assertEquals("theme-asset", delete.resourceType());
        assertEquals("a-1", delete.resourceId());
        assertEquals("DENIED", delete.outcome());
        assertEquals("THEME_UPDATE", map("PUT", "/admin/realms/gov/theme", 200).type());
    }
}
