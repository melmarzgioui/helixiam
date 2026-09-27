/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.service;

import io.helixiam.authorization.amqp.ServiceProviderPublisher;
import io.helixiam.authorization.amqp.realm.RealmSettingsDto;
import io.helixiam.authorization.domain.ServiceProviderOAuthClient;
import io.helixiam.authorization.security.realm.RealmSettingsResolver;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/** Review rc.3 #2: realm token lifetimes apply only where the client sets none. */
class RegisteredClientRealmLifetimeTest {

    private static RegisteredClient client(final Integer access, final Integer refresh) {
        final ServiceProviderOAuthClient c = new ServiceProviderOAuthClient();
        c.setServiceProviderId("id-1");
        c.setClientId("web");
        c.setAuthorizationGrantTypes("client_credentials");
        c.setScopes("openid");
        c.setAccessTokenLifespan(access);
        c.setRefreshTokenLifespan(refresh);
        return ServiceProviderOAuthClient.build(c);
    }

    private static RegisteredClientRepositoryService repo() {
        final RegisteredClientRepositoryService repo = new RegisteredClientRepositoryService(mock(ServiceProviderPublisher.class));
        final RealmSettingsResolver resolver = mock(RealmSettingsResolver.class);
        final RealmSettingsDto realm = mock(RealmSettingsDto.class);
        when(realm.accessTokenTtlSeconds()).thenReturn(300);
        when(realm.refreshTokenTtlSeconds()).thenReturn(86_400);
        when(resolver.get(any())).thenReturn(realm);
        repo.setRealmSettings(resolver);
        return repo;
    }

    @Test
    void noClientLifetimes_takeTheRealms() {
        final RegisteredClient out = repo().withRealmLifetimes(client(null, null));
        assertThat(out.getTokenSettings().getAccessTokenTimeToLive()).isEqualTo(Duration.ofSeconds(300));
        assertThat(out.getTokenSettings().getRefreshTokenTimeToLive()).isEqualTo(Duration.ofSeconds(86_400));
    }

    @Test
    void clientLifetimes_win() {
        final RegisteredClient out = repo().withRealmLifetimes(client(120, 600));
        assertThat(out.getTokenSettings().getAccessTokenTimeToLive()).isEqualTo(Duration.ofSeconds(120));
        assertThat(out.getTokenSettings().getRefreshTokenTimeToLive()).isEqualTo(Duration.ofSeconds(600));
    }
}
