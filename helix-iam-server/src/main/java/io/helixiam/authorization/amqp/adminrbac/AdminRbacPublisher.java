/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.amqp.adminrbac;


import java.util.List;

/**
 * Helix IAM: fine-grained admin RBAC seam onto the user-domain store (owned by the subscriber).
 * JSON-marshalled two-copy DTOs, like the user-admin exchange (E8.5).
 * <p>
 * dash→dot GOTCHA: the subscriber derives its binding routing key by replacing EVERY dash in the dashed
 * queue name with a dot, so the routing keys here MUST be fully dot-delimited (no dashes) to match.
 */
public interface AdminRbacPublisher {

    String EXCHANGE_AUTHORIZATION_ADMIN_RBAC = "exchange-authorization-adminrbac";
    String ADMIN_RBAC_CATALOG = "authorization.adminrbac.catalog";
    String ADMIN_RBAC_ROLES = "authorization.adminrbac.roles";
    String ADMIN_RBAC_SET = "authorization.adminrbac.set";
    String ADMIN_RBAC_EFFECTIVE = "authorization.adminrbac.effective";

    /** The full catalogue of admin permissions (matrix columns). {@code arg} is ignored. */
    List<AdminPermissionDto> catalog(final String arg);

    /** Every realm role with the admin-permission keys it grants (matrix rows). */
    List<AdminRoleGrantsDto> roles(final String realmId);

    /** Replace the complete set of admin permissions for one role; returns the persisted grants. */
    AdminRoleGrantsDto set(final AdminRoleGrantWriteDto write);

    /** Resolve a principal's effective admin permissions (used by the enforcement manager). */
    AdminEffectivePermissionsDto effective(final AdminEffectivePermissionsRef ref);
}
