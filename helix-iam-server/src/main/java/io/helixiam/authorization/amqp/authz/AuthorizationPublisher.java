/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.amqp.authz;


import java.util.List;

/** Helix IAM (Wave 6): the Authorization-Services admin API's seam onto the realm-domain store. */
public interface AuthorizationPublisher {

    String EXCHANGE_AUTHORIZATION_AUTHZ = "exchange-authorization-authz";

    AuthzServerDto getServer(AuthzRef ref);

    AuthzServerDto setServer(AuthzServerDto write);

    List<AuthzScopeDto> listScopes(AuthzRef ref);

    AuthzScopeDto createScope(AuthzScopeDto write);

    Boolean deleteScope(AuthzRef ref);

    List<AuthzResourceDto> listResources(AuthzRef ref);

    AuthzResourceDto createResource(AuthzResourceDto write);

    Boolean deleteResource(AuthzRef ref);

    List<AuthzPolicyDto> listPolicies(AuthzRef ref);

    AuthzPolicyDto createPolicy(AuthzPolicyDto write);

    Boolean deletePolicy(AuthzRef ref);

    List<AuthzPermissionDto> listPermissions(AuthzRef ref);

    AuthzPermissionDto createPermission(AuthzPermissionDto write);

    Boolean deletePermission(AuthzRef ref);

    AuthzEvalResult evaluate(AuthzEvalRequest req);
}
