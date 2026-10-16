/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.security.adminrbac;

import java.util.Optional;

/**
 * Helix IAM: maps a matched {@code /admin/**} request (path + HTTP method) to the admin-permission KEY it
 * requires — the Keycloak {@code realm-management} resource→scope mapping for the console's controller groups.
 * <p>
 * Pure + side-effect-free so it is unit-testable. Read (GET/HEAD) maps to the {@code view-*} permission where a
 * view/manage split exists, otherwise the same permission covers both. An unknown {@code /admin/**} path that
 * isn't realm-scoped (e.g. {@code /admin/audit/config}) falls back to {@code manage-realm}. Returns empty for
 * non-{@code /admin} paths (those are never enforced by the admin manager).
 */
public final class AdminRoutePermissions {

    // Permission keys (mirror of AdminPermission.key() on the subscriber — kept as constants to avoid coupling).
    public static final String REALM_ADMIN = "realm-admin";
    public static final String VIEW_USERS = "view-users";
    public static final String MANAGE_USERS = "manage-users";
    public static final String VIEW_CLIENTS = "view-clients";
    public static final String MANAGE_CLIENTS = "manage-clients";
    public static final String MANAGE_ROLES = "manage-roles";
    public static final String VIEW_IDENTITY_PROVIDERS = "view-identity-providers";
    public static final String MANAGE_IDENTITY_PROVIDERS = "manage-identity-providers";
    public static final String MANAGE_AUTHORIZATION = "manage-authorization";
    public static final String MANAGE_ORGANIZATIONS = "manage-organizations";
    public static final String MANAGE_REALM = "manage-realm";
    public static final String VIEW_EVENTS = "view-events";
    public static final String MANAGE_EVENTS = "manage-events";

    private AdminRoutePermissions() {
    }

    /** True for read-only methods (which map to the {@code view-*} permission where applicable). */
    private static boolean isRead(final String method) {
        return "GET".equalsIgnoreCase(method) || "HEAD".equalsIgnoreCase(method) || "OPTIONS".equalsIgnoreCase(method);
    }

    /**
     * Required permission key for {@code path} + {@code method}, or empty if the path is not an {@code /admin}
     * path. The admin-RBAC management API itself ({@code .../admin-roles}) requires {@code realm-admin}.
     */
    public static Optional<String> required(final String path, final String method) {
        if (path == null || !path.startsWith("/admin")) {
            return Optional.empty();
        }
        final boolean read = isRead(method);

        // Segments are matched exactly and case-sensitively, on the DECODED path (AdminAuthorizationManager passes
        // the path Spring MVC routes on). Anything not listed here fails closed to realm-admin.
        final String[] seg = (path.startsWith("/") ? path.substring(1) : path).split("/", -1);
        if (seg.length >= 2 && "audit".equals(seg[1])) {
            return Optional.of(MANAGE_EVENTS); // realm-independent audit config
        }
        if (seg.length == 2 && ("metrics".equals(seg[1]) || "realms".equals(seg[1]))) {
            return Optional.of(MANAGE_REALM); // /admin/metrics, /admin/realms (list)
        }
        if (seg.length < 3 || !"realms".equals(seg[1])) {
            return Optional.of(REALM_ADMIN); // an unknown realm-independent admin path
        }
        if (seg.length == 3) {
            return Optional.of(MANAGE_REALM); // /admin/realms/{realmId}
        }

        // Realm-scoped resource groups: /admin/realms/{realmId}/<group>...
        final String group = seg[3];
        // The signing settings decide which key and algorithm sign tokens and SAML: realm-admin, like key writes.
        if ("settings".equals(group) && seg.length >= 5 && "signing".equals(seg[4]) && !read) {
            return Optional.of(REALM_ADMIN);
        }
        return Optional.of(switch (group) {
            case "users" -> read ? VIEW_USERS : MANAGE_USERS;
            case "clients", "applications", "saml-clients", "client-scopes" -> read ? VIEW_CLIENTS : MANAGE_CLIENTS;
            case "claims" -> MANAGE_AUTHORIZATION;
            // Task 24: the EUDI wallet's verifier access keys and the wallet form's helpers (metadata, certificate
            // preview) are identity-provider management, read and write.
            case "identity-providers", "verifier-keys", "wallet" -> MANAGE_IDENTITY_PROVIDERS;
            // pentest-b INFO: trusted lists have a view/manage split — a view-only admin can read them.
            case "trusted-lists" -> read ? VIEW_IDENTITY_PROVIDERS : MANAGE_IDENTITY_PROVIDERS;
            case "groups", "organizations" -> MANAGE_ORGANIZATIONS;
            case "flows", "authenticators", "authorization" -> MANAGE_AUTHORIZATION;
            case "sessions" -> read ? VIEW_EVENTS : MANAGE_EVENTS;
            // Structured theming: the realm theme (read and write) is realm configuration; organization themes
            // (/organizations/{id}/theme) fall under the "organizations" group → manage-organizations.
            case "settings", "theme", "messaging", "provisioning", "endpoints", "health", "subject-claim" -> MANAGE_REALM;
            // roles + per-user role mappings (RoleAdminController is mapped at /admin/realms/{realmId})
            case "roles" -> MANAGE_ROLES;
            // BYO realm keys (security review): whoever imports or activates a signing key can mint any token of the
            // realm, admin service-account tokens included — so every key write needs a full realm admin.
            case "keys" -> read ? MANAGE_REALM : REALM_ADMIN;
            // The admin-RBAC management API is the most sensitive — only full realm admins may grant permissions.
            case "admin-roles" -> REALM_ADMIN;
            // Groups that relied on the old manage-realm default, listed explicitly (security review: unknown
            // groups now fail closed to realm-admin).
            case "agents", "events", "scim-targets", "webhooks", "workload-identity", "user-federation", "flow",
                 "flow-engine", "export", "import", "" -> MANAGE_REALM;
            // /admin/realms/{realmId}/users/{userId}/roles is covered by the "users" case above.
            default -> REALM_ADMIN;
        });
    }
}
