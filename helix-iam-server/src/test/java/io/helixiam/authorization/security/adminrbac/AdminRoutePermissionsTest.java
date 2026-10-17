/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

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
        // Open issue E7: revoking every session of a user is a users write.
        assertThat(AdminRoutePermissions.required("/admin/realms/gov/users/u-1/sessions", "DELETE"))
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
    void walletVerifierKeysAndWalletMetadata_requireManageIdentityProviders() {
        // Task 24: the verifier access keys and the wallet console helpers belong to identity-provider management.
        for (final String method : new String[] {"GET", "POST"}) {
            assertThat(AdminRoutePermissions.required("/admin/realms/gov/verifier-keys", method))
                    .contains("manage-identity-providers");
        }
        assertThat(AdminRoutePermissions.required("/admin/realms/gov/wallet/metadata", "GET"))
                .contains("manage-identity-providers");
        assertThat(AdminRoutePermissions.required("/admin/realms/gov/wallet/certificates/preview", "POST"))
                .contains("manage-identity-providers");
    }

    @Test
    void trustedLists_splitsViewVsManage() {
        // pentest-b INFO: a view-only admin must be able to read trusted lists without manage-identity-providers.
        assertThat(AdminRoutePermissions.required("/admin/realms/gov/trusted-lists", "GET"))
                .contains("view-identity-providers");
        assertThat(AdminRoutePermissions.required("/admin/realms/gov/trusted-lists/tl-1", "GET"))
                .contains("view-identity-providers");
        assertThat(AdminRoutePermissions.required("/admin/realms/gov/trusted-lists", "POST"))
                .contains("manage-identity-providers");
        assertThat(AdminRoutePermissions.required("/admin/realms/gov/trusted-lists/tl-1", "DELETE"))
                .contains("manage-identity-providers");
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
    void unknownRealmScopedGroup_failsClosedToRealmAdmin() {
        assertThat(AdminRoutePermissions.required("/admin/realms/gov/something-new", "POST")).contains("realm-admin");
        assertThat(AdminRoutePermissions.required("/admin/realms/gov/something-new", "GET")).contains("realm-admin");
        // Case matters (Spring MVC matching is case-sensitive): KEYS is not keys — and fails closed.
        assertThat(AdminRoutePermissions.required("/admin/realms/gov/KEYS/import", "POST")).contains("realm-admin");
        assertThat(AdminRoutePermissions.required("/admin/realms/gov/Users", "POST")).contains("realm-admin");
        assertThat(AdminRoutePermissions.required("/admin/other", "GET")).contains("realm-admin");
    }

    @Test
    void groupsThatUsedTheDefault_areListedExplicitly() {
        for (final String g : new String[] {"agents", "events", "scim-targets", "webhooks", "workload-identity",
                "user-federation", "flow", "flow-engine", "export", "import"}) {
            assertThat(AdminRoutePermissions.required("/admin/realms/gov/" + g, "POST")).as(g).contains("manage-realm");
        }
        assertThat(AdminRoutePermissions.required("/admin/realms/gov", "GET")).contains("manage-realm");
        assertThat(AdminRoutePermissions.required("/admin/realms", "GET")).contains("manage-realm");
        assertThat(AdminRoutePermissions.required("/admin/metrics", "GET")).contains("manage-realm");
        assertThat(AdminRoutePermissions.required("/admin/realms/gov/admin-roles/r1", "PUT")).contains("realm-admin");
        // Only the group segment decides: an "admin-roles" deeper in the path is not the admin-RBAC API.
        assertThat(AdminRoutePermissions.required("/admin/realms/gov/users/admin-roles", "GET")).contains("view-users");
    }

    @Test
    void themes_realmNeedsManageRealm_organizationNeedsManageOrganizations() {
        for (final String method : new String[] {"GET", "PUT"}) {
            assertThat(AdminRoutePermissions.required("/admin/realms/gov/theme", method)).contains("manage-realm");
            // File themes (spec §5): selecting the realm's file theme is realm configuration too.
            assertThat(AdminRoutePermissions.required("/admin/realms/gov/theme/base", method)).contains("manage-realm");
            assertThat(AdminRoutePermissions.required("/admin/realms/gov/organizations/o-1/theme", method))
                    .contains("manage-organizations");
        }
    }

    @Test
    void signingSettingsWrites_needRealmAdmin() {
        assertThat(AdminRoutePermissions.required("/admin/realms/gov/settings/signing", "PUT")).contains("realm-admin");
        assertThat(AdminRoutePermissions.required("/admin/realms/gov/settings/signing", "GET")).contains("manage-realm");
        assertThat(AdminRoutePermissions.required("/admin/realms/gov/settings", "PUT")).contains("manage-realm");
    }

    @Test
    void realmKeyWrites_needRealmAdmin_readsKeepManageRealm() {
        assertThat(AdminRoutePermissions.required("/admin/realms/gov/keys", "GET")).contains("manage-realm");
        assertThat(AdminRoutePermissions.required("/admin/realms/gov/keys/k1/csr", "GET")).contains("manage-realm");
        for (final String[] w : new String[][] {{"POST", "/keys/import"}, {"POST", "/keys/csr"},
                {"PUT", "/keys/k1/certificate"}, {"POST", "/keys/k1/activate"}, {"POST", "/keys/rotate"},
                {"DELETE", "/keys/k1"}}) {
            assertThat(AdminRoutePermissions.required("/admin/realms/gov" + w[1], w[0])).as(w[1]).contains("realm-admin");
        }
    }

    @Test
    void trustInAFederatedLinkIsARealmAdminsDecision() {
        final String base = "/admin/realms/gov/users/u1/federated-identities";
        assertThat(AdminRoutePermissions.required(base, "GET")).contains("view-users");
        assertThat(AdminRoutePermissions.required(base + "/corp/confirm", "POST")).contains("realm-admin");
        assertThat(AdminRoutePermissions.required(base + "/corp/revoke-trust", "POST")).contains("realm-admin");
    }
}
