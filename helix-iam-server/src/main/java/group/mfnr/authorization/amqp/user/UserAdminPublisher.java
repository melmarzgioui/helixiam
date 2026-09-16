package group.mfnr.authorization.amqp.user;


import java.util.List;

/**
 * Helix IAM E8.5: the Users admin API's seam onto the user-domain store (owned by the subscriber).
 * JSON-marshalled two-copy DTOs, like the identity-provider exchange (E8.2).
 */
public interface UserAdminPublisher {

    String EXCHANGE_AUTHORIZATION_USER_ADMIN = "exchange-authorization-user-admin";
    String USER_ADMIN_LIST = "authorization.user.admin.list";
    String USER_ADMIN_GET = "authorization.user.admin.get";
    String USER_ADMIN_CREATE = "authorization.user.admin.create";
    String USER_ADMIN_UPDATE = "authorization.user.admin.update";
    String USER_ADMIN_RESET_PASSWORD = "authorization.user.admin.reset.password";
    // (6) Self-service: change own password (verify current → set new). Fully dot-delimited to match the
    // subscriber's dash→dot binding (authorization-user-admin-change-password).
    String USER_ADMIN_CHANGE_PASSWORD = "authorization.user.admin.change.password";
    String USER_ADMIN_DELETE = "authorization.user.admin.delete";
    // NOTE: the subscriber derives its binding routing key by replacing EVERY dash in the dashed queue
    // name with a dot, so the publisher routing key here must be fully dot-delimited (no dashes) to match.
    String USER_ADMIN_LIST_CREDENTIALS = "authorization.user.admin.list.credentials";
    String USER_ADMIN_REVOKE_CREDENTIAL = "authorization.user.admin.revoke.credential";
    // B1: required actions (set replacement list / read pending / clear one completed action).
    String USER_ADMIN_SET_REQUIRED_ACTIONS = "authorization.user.admin.set.required.actions";
    String USER_ADMIN_GET_REQUIRED_ACTIONS = "authorization.user.admin.get.required.actions";
    String USER_ADMIN_CLEAR_REQUIRED_ACTION = "authorization.user.admin.clear.required.action";

    /** All users bound to a realm. */
    List<UserAdminDto> list(final String realmId);

    /** A single realm user, or {@code null} if none. */
    UserAdminDto get(final UserAdminRef ref);

    /** Create a realm user; returns the persisted state. */
    UserAdminDto create(final UserWriteDto write);

    /** Update a realm user's flags + attributes; returns the persisted state ({@code null} if absent). */
    UserAdminDto update(final UserWriteDto write);

    /** Set a new password; {@code false} if the user does not exist. */
    Boolean resetPassword(final UserPasswordDto reset);

    /** Change own password (verify current → set new); {@code false} if absent or the current password is wrong. */
    Boolean changePassword(final UserChangePasswordDto change);

    /** Remove a user from the realm; {@code false} if it was not a member. */
    Boolean delete(final UserAdminRef ref);

    /** Every enrolled authentication factor for a realm user (passkeys, devices, TOTP/HOTP, recovery codes). */
    List<CredentialSummary> listCredentials(final UserAdminRef ref);

    /** Revoke one factor by (type, id); {@code false} if it is absent or not owned by the user. */
    Boolean revokeCredential(final CredentialRevokeRef ref);

    /** B1: replace a user's required-actions list (CSV); {@code false} if the user does not exist. */
    Boolean setRequiredActions(final UserRequiredActionsDto dto);

    /** B1: the user's pending required-actions CSV ({@code null}/blank = none). */
    String getRequiredActions(final String userId);

    /** B1: remove one completed action (in {@code dto.requiredActions()}); returns the remaining CSV. */
    String clearRequiredAction(final UserRequiredActionsDto dto);
}
