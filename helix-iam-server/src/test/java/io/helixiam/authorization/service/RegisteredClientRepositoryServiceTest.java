/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.service;

import io.helixiam.authorization.support.RealmScopedKey;
import io.helixiam.authorization.amqp.ServiceProviderPublisher;
import io.helixiam.authorization.security.realm.RealmContextHolder;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Helix IAM multi-tenant (MT-3): the client lookup is scoped to the realm of the in-flight
 * {@code /realms/{realm}/…} request — the realm is packed ahead of the id over AMQP.
 */
class RegisteredClientRepositoryServiceTest {

    @AfterEach
    void clear() {
        RealmContextHolder.clear();
    }

    @Test
    void findByClientId_packsTheCurrentRealm() {
        final ServiceProviderPublisher publisher = mock(ServiceProviderPublisher.class);
        final RegisteredClientRepositoryService service = new RegisteredClientRepositoryService(publisher);

        RealmContextHolder.set("gov");
        service.findByClientId("acme");

        verify(publisher).findByClientId(eq(RealmScopedKey.pack("gov", "acme")));
    }

    @Test
    void findById_outsideAnyRealm_defaultsToMaster() {
        final ServiceProviderPublisher publisher = mock(ServiceProviderPublisher.class);
        final RegisteredClientRepositoryService service = new RegisteredClientRepositoryService(publisher);

        // No RealmContextHolder set (e.g. /admin/** path): defaults to the admin realm.
        service.findById("sp-1");

        verify(publisher).findById(eq(RealmScopedKey.pack("master", "sp-1")));
    }

    @Test
    void notFoundSentinel_fromASubscriber_resolvesToNull() {
        final ServiceProviderPublisher publisher = mock(ServiceProviderPublisher.class);
        final RegisteredClient sentinel = RegisteredClient.withId(RealmScopedKey.NOT_FOUND_CLIENT_ID)
                .clientId(RealmScopedKey.NOT_FOUND_CLIENT_ID)
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .clientSecret("{noop}x")
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .build();
        when(publisher.findByClientId(any())).thenReturn(sentinel);

        final RegisteredClientRepositoryService service = new RegisteredClientRepositoryService(publisher);

        // The cross-realm sentinel must not surface as a usable client — SAS sees null → invalid_client.
        assertThat(service.findByClientId("ghost")).isNull();
    }
}
