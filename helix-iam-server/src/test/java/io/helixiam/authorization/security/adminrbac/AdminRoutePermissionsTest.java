package io.helixiam.authorization.security.adminrbac;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/** Helix IAM: route group → required admin-permission key mapping (read/write split). */
class AdminRoutePermissionsTest {

    @Test
    void usersGroup_splitsViewVsManage() {
        assertThat(AdminRoutePermissions.required("/admin/realms/gov/users", "GET")).contains("view-users");
        assertThat(AdminRoutePermissions.required("/admin/realms/gov/users", "POST")).contains("manage-users");
        assertThat(AdminRoutePermissions.required("/admin/realms/gov/users/u-1/credentials", "DELETE"))
                .contains("manage-users");
    }

    @Test
    void clientFamily_mapsToClientPermissions() {
        assertThat(AdminRoutePermissions.required("/admin/realms/gov/clients", "GET")).contains("view-clients");
        assertThat(AdminRoutePermissions.required("/admin/realms/gov/applications", "POST")).contains("manage-clients");
        assertThat(AdminRoutePermissions.required("/admin/realms/gov/saml-clients", "PUT")).contains("manage-clients");
        assertThat(AdminRoutePermissions.required("/admin/realms/gov/client-scopes", "POST")).contains("manage-clients");
    }

    @Test
    void rolesGroup_requiresManageRoles() {
        assertThat(AdminRoutePermissions.required("/admin/realms/gov/roles", "POST")).contains("manage-roles");
    }

    @Test
    void identityProviders_andAuthorizationGroups() {
        assertThat(AdminRoutePermissions.required("/admin/realms/gov/identity-providers", "POST"))
                .contains("manage-identity-providers");
        assertThat(AdminRoutePermissions.required("/admin/realms/gov/flows", "POST")).contains("manage-authorization");
        assertThat(AdminRoutePermissions.required("/admin/realms/gov/claims", "POST")).contains("manage-authorization");
    }

    @Test
    void sessionsGroup_splitsViewVsManage() {
        assertThat(AdminRoutePermissions.required("/admin/realms/gov/sessions", "GET")).contains("view-events");
        assertThat(AdminRoutePermissions.required("/admin/realms/gov/sessions/s-1", "DELETE")).contains("manage-events");
    }

    @Test
    void organizationsAndGroups_mapToManageOrganizations() {
        assertThat(AdminRoutePermissions.required("/admin/realms/gov/groups", "POST")).contains("manage-organizations");
    }

    @Test
    void realmConfigGroups_mapToManageRealm() {
        assertThat(AdminRoutePermissions.required("/admin/realms/gov/settings", "PUT")).contains("manage-realm");
        assertThat(AdminRoutePermissions.required("/admin/realms/gov/provisioning", "PUT")).contains("manage-realm");
        assertThat(AdminRoutePermissions.required("/admin/realms/gov/messaging/templates", "POST"))
                .contains("manage-realm");
    }

    @Test
    void adminRbacApiItself_requiresRealmAdmin() {
        assertThat(AdminRoutePermissions.required("/admin/realms/gov/admin-roles", "GET")).contains("realm-admin");
        assertThat(AdminRoutePermissions.required("/admin/realms/gov/admin-roles/r-1", "PUT")).contains("realm-admin");
    }

    @Test
    void auditConfig_requiresManageEvents() {
        assertThat(AdminRoutePermissions.required("/admin/audit/config", "PUT")).contains("manage-events");
    }

    @Test
    void nonAdminPath_isEmpty() {
        assertThat(AdminRoutePermissions.required("/login", "GET")).isEmpty();
        assertThat(AdminRoutePermissions.required("/oauth2/token", "POST")).isEmpty();
        assertThat(AdminRoutePermissions.required(null, "GET")).isEmpty();
    }

    @Test
    void unknownRealmScopedGroup_fallsBackToManageRealm() {
        assertThat(AdminRoutePermissions.required("/admin/realms/gov/something-new", "POST")).contains("manage-realm");
    }
}
