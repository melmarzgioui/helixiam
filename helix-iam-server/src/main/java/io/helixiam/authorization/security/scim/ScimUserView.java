package io.helixiam.authorization.security.scim;

/**
 * Helix IAM B7: the minimal local-user projection the outbound SCIM dispatcher needs to provision a user
 * into a downstream service provider. Built from the admin API's {@code UserAdminDto} at the lifecycle
 * choke-points (create / update / delete). {@code userId} is carried to the SCIM {@code externalId} as the
 * stable linking key, so updates/deletes can locate the remote resource without storing a mapping.
 */
public record ScimUserView(String userId, String username, String email, boolean active,
                           String firstName, String lastName) {
}
