package group.mfnr.authorization.amqp.role;


import java.util.List;

/**
 * Helix IAM E8.5-S2: the Roles admin API's seam onto the role-domain store (owned by the subscriber).
 */
public interface RoleAdminPublisher {

    String EXCHANGE_AUTHORIZATION_ROLE_ADMIN = "exchange-authorization-role-admin";
    String ROLE_ADMIN_LIST = "authorization.role.admin.list";
    String ROLE_ADMIN_CREATE = "authorization.role.admin.create";
    String ROLE_ADMIN_DELETE = "authorization.role.admin.delete";
    String ROLE_ADMIN_USER_ROLES = "authorization.role.admin.userroles";
    String ROLE_ADMIN_ASSIGN = "authorization.role.admin.assign";
    String ROLE_ADMIN_UNASSIGN = "authorization.role.admin.unassign";
    String ROLE_ADMIN_SET_DEFAULT = "authorization.role.admin.setdefault";

    /** All roles defined in a realm. */
    List<RoleDto> list(final String realmId);

    /** Create a realm role (idempotent on name); returns the role. */
    RoleDto create(final RoleRef ref);

    /** Remove a realm role and its assignments; {@code false} if not in the realm. */
    Boolean delete(final RoleRef ref);

    /** The realm roles assigned to a user. */
    List<RoleDto> userRoles(final RoleAssignment ref);

    /** Grant a role to a user; {@code false} if the user isn't a realm member. */
    Boolean assign(final RoleAssignment ref);

    /** Revoke a role from a user; {@code false} if it wasn't assigned. */
    Boolean unassign(final RoleAssignment ref);

    /** Designate a realm's default role (auto-assigned to new users); returns the updated role, or {@code null}. */
    RoleDto setDefault(final RoleRef ref);
}
