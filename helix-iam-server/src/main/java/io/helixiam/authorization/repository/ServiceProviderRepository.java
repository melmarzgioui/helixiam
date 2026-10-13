/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.repository;

import io.helixiam.authorization.domain.ServiceProviderOAuthClient;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface ServiceProviderRepository extends JpaRepository<ServiceProviderOAuthClient, String> {
    Optional<ServiceProviderOAuthClient> findByClientIdAndDeleted(final String clientId, final boolean deleted);
    Optional<ServiceProviderOAuthClient> findByIdAndDeleted(final String clientId, final boolean deleted);
    // Helix IAM multi-tenant (MT-3): realm-scoped lookups so a client under /realms/{realm} resolves
    // only when it belongs to {realm}; cross-realm use returns empty (rejected).
    Optional<ServiceProviderOAuthClient> findByClientIdAndRealmIdAndDeleted(final String clientId, final String realmId, final boolean deleted);
    Optional<ServiceProviderOAuthClient> findByIdAndRealmIdAndDeleted(final String id, final String realmId, final boolean deleted);
    List<ServiceProviderOAuthClient> findAllByTenantIdAndDeleted(final String tenantId, final boolean deleted);
    /** Helix IAM (CORS): all live clients in a realm, to collect their allowed web origins. */
    List<ServiceProviderOAuthClient> findAllByRealmIdAndDeleted(final String realmId, final boolean deleted);
    /** Helix IAM (Application model): the live OIDC clients linked to an Application, for cascade-delete. */
    List<ServiceProviderOAuthClient> findAllByApplicationIdAndDeleted(final String applicationId, final boolean deleted);
    boolean existsByClientIdAndDeleted(final String clientId, final boolean deleted);

    /** private_key_jwt clients without a JWKS URL (they cannot authenticate with a key). */
    @org.springframework.data.jpa.repository.Query("SELECT c FROM ServiceProviderOAuthClient c WHERE c.deleted = false"
            + " AND c.tokenEndpointAuthMethod = 'PRIVATE_KEY_JWT' AND (c.jwksUrl IS NULL OR c.jwksUrl = '')")
    List<ServiceProviderOAuthClient> findPrivateKeyJwtWithoutJwksUrl();

    /** private_key_jwt clients with a JWKS URL (the startup audit checks the URL's scheme). */
    @org.springframework.data.jpa.repository.Query("SELECT c FROM ServiceProviderOAuthClient c WHERE c.deleted = false"
            + " AND c.tokenEndpointAuthMethod = 'PRIVATE_KEY_JWT' AND c.jwksUrl IS NOT NULL AND c.jwksUrl <> ''")
    List<ServiceProviderOAuthClient> findPrivateKeyJwtWithJwksUrl();
}
