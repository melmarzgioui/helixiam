/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.service;

import io.helixiam.authorization.domain.ServiceProviderOAuthClient;
import io.helixiam.authorization.repository.ServiceProviderRepository;
import org.junit.jupiter.api.Test;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Helix IAM multi-tenant (MT-3): a client resolves only within its own realm — a lookup under another
 * realm's path returns {@code null} (cross-realm use rejected).
 */
class ServiceProviderServiceTest {

    private static ServiceProviderOAuthClient client(final String clientId, final String realm) {
        final ServiceProviderOAuthClient c = new ServiceProviderOAuthClient();
        c.setClientId(clientId);
        c.setClientSecret("noop-secret");
        c.setRealmId(realm);
        c.setScopes("openid");
        c.setAuthorizationGrantTypes("client_credentials");
        return c;
    }

    @Test
    void getRegisteredClientByClientId_withinItsRealm_resolves() {
        final ServiceProviderRepository repo = mock(ServiceProviderRepository.class);
        when(repo.findByClientIdAndRealmIdAndDeleted("acme", "gov", false))
                .thenReturn(Optional.of(client("acme", "gov")));

        final ServiceProviderService service = new ServiceProviderService(repo, org.mockito.Mockito.mock(io.helixiam.authorization.repository.application.ApplicationRepository.class), "/nonexistent");

        assertNotNull(service.getRegisteredClientByClientId("acme", "gov"));
        assertEquals("acme", service.getRegisteredClientByClientId("acme", "gov").getClientId());
    }

    @Test
    void getRegisteredClientByClientId_underAnotherRealm_isRejected() {
        final ServiceProviderRepository repo = mock(ServiceProviderRepository.class);
        // acme belongs to gov; a lookup under master finds nothing.
        when(repo.findByClientIdAndRealmIdAndDeleted("acme", "master", false))
                .thenReturn(Optional.empty());

        final ServiceProviderService service = new ServiceProviderService(repo, org.mockito.Mockito.mock(io.helixiam.authorization.repository.application.ApplicationRepository.class), "/nonexistent");

        assertNull(service.getRegisteredClientByClientId("acme", "master"));
    }
}
