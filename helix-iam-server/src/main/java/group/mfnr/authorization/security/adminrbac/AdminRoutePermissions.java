package group.mfnr.authorization.security.adminrbac;

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

        // The admin-RBAC management API is the most sensitive — only full realm admins may grant permissions.
        if (path.contains("/admin-roles")) {
            return Optional.of(REALM_ADMIN);
        }
        // Realm-independent audit config.
        if (path.startsWith("/admin/audit")) {
            return Optional.of(MANAGE_EVENTS);
        }

        // Realm-scoped resource groups: /admin/realms/{realmId}/<group>...
        final String group = realmGroup(path);
        return Optional.of(switch (group) {
            case "users" -> read ? VIEW_USERS : MANAGE_USERS;
            case "clients", "applications", "saml-clients", "client-scopes" -> read ? VIEW_CLIENTS : MANAGE_CLIENTS;
            case "claims" -> MANAGE_AUTHORIZATION;
            case "identity-providers" -> MANAGE_IDENTITY_PROVIDERS;
            case "groups", "organizations" -> MANAGE_ORGANIZATIONS;
            case "flows", "authenticators", "authorization" -> MANAGE_AUTHORIZATION;
            case "sessions" -> read ? VIEW_EVENTS : MANAGE_EVENTS;
            case "settings", "messaging", "provisioning", "endpoints", "health", "subject-claim" -> MANAGE_REALM;
            // roles + per-user role mappings (RoleAdminController is mapped at /admin/realms/{realmId})
            case "roles" -> MANAGE_ROLES;
            // /admin/realms/{realmId}/users/{userId}/roles is covered by the "users" case above.
            default -> MANAGE_REALM;
        });
    }

    /**
     * The first path segment after {@code /admin/realms/{realmId}/}. Empty string when the path is shorter
     * (e.g. {@code /admin/realms/{realmId}}), which falls through to the {@code manage-realm} default.
     */
    private static String realmGroup(final String path) {
        // strip leading slash, split: admin / realms / {realmId} / <group> / ...
        final String[] seg = path.startsWith("/") ? path.substring(1).split("/") : path.split("/");
        if (seg.length >= 4 && "realms".equals(seg[1])) {
            return seg[3];
        }
        return "";
    }
}
