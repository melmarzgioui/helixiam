/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.amqp.clientrole;


import java.util.List;

/**
 * Helix IAM (Wave 4): the client-roles + service-account-roles admin API's seam onto the client-domain
 * store. {@link #serviceAccountRoleNames} is the runtime lookup the token customizer uses at issuance.
 */
public interface ClientRolePublisher {

    String EXCHANGE_AUTHORIZATION_CLIENT_ROLE = "exchange-authorization-client-role";
    String ROLE_LIST = "authorization.client.role.list";
    String ROLE_CREATE = "authorization.client.role.create";
    String ROLE_DELETE = "authorization.client.role.delete";
    String SAROLE_LIST = "authorization.client.sarole.list";
    String SAROLE_ASSIGN = "authorization.client.sarole.assign";
    String SAROLE_UNASSIGN = "authorization.client.sarole.unassign";
    String SAROLE_NAMES = "authorization.client.sarole.names";
    String SAROLE_FOR_CLIENT = "authorization.client.sarole.forclient";

    List<ClientRoleDto> listRoles(final ClientRoleRef ref);

    ClientRoleDto createRole(final ClientRoleWriteDto write);

    Boolean deleteRole(final ClientRoleRef ref);

    List<ServiceAccountRoleDto> listServiceAccountRoles(final ClientRoleRef ref);

    ServiceAccountRoleDto assignServiceAccountRole(final ServiceAccountRoleDto write);

    Boolean unassignServiceAccountRole(final ServiceAccountRoleDto ref);

    /** Role names granted to a client's service account (by clientId); empty when none/unknown. */
    List<String> serviceAccountRoleNames(final String clientId);

    /**
     * Typed (REALM/CLIENT) roles granted to a client's service account (by clientId); empty when
     * none/unknown. The token customizer uses this to namespace roles into {@code realm_access}/
     * {@code resource_access}.
     */
    List<ServiceAccountRoleDto> serviceAccountRoles(final String clientId);
}
