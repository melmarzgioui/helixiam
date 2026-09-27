/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.service;

import io.helixiam.authorization.support.RealmScopedKey;
import io.helixiam.authorization.amqp.ServiceProviderPublisher;
import io.helixiam.authorization.security.realm.RealmContextHolder;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Service;

@Service
public class RegisteredClientRepositoryService implements RegisteredClientRepository {

    private final ServiceProviderPublisher serviceProviderPublisher;
    private io.helixiam.authorization.security.realm.RealmSettingsResolver realmSettings;

    public RegisteredClientRepositoryService(final ServiceProviderPublisher serviceProviderPublisher) {
        this.serviceProviderPublisher = serviceProviderPublisher;
    }

    @org.springframework.beans.factory.annotation.Autowired(required = false)
    public void setRealmSettings(final io.helixiam.authorization.security.realm.RealmSettingsResolver realmSettings) {
        this.realmSettings = realmSettings;
    }

    @Override
    public void save(final RegisteredClient registeredClient) {
        // We like to swallow
    }

    @Override
    public RegisteredClient findById(final String id) {
        // MT-3: scope to the realm of the in-flight /realms/{realm}/… request (null → master).
        return withRealmLifetimes(unwrap(serviceProviderPublisher.findById(RealmScopedKey.pack(RealmContextHolder.get(), id))));
    }

    @Override
    public RegisteredClient findByClientId(final String clientId) {
        return withRealmLifetimes(unwrap(serviceProviderPublisher.findByClientId(RealmScopedKey.pack(RealmContextHolder.get(), clientId))));
    }

    /**
     * MT-3: the subscriber returns a sentinel (not {@code null}) for a not-found / cross-realm lookup, so the
     * serialized AMQP reply is never empty — an empty reply would block the caller for the full reply timeout.
     * Map the sentinel back to {@code null} so the Spring Authorization Server resolves it as {@code invalid_client}.
     */
    private static RegisteredClient unwrap(final RegisteredClient client) {
        return (client != null && RealmScopedKey.NOT_FOUND_CLIENT_ID.equals(client.getClientId())) ? null : client;
    }

    /**
     * Review rc.3 #2: a client that does not set its own access/refresh token lifetime gets the realm's
     * ({@code accessTokenTtlSeconds} / {@code refreshTokenTtlSeconds}) instead of the built-in default.
     */
    RegisteredClient withRealmLifetimes(final RegisteredClient client) {
        if (client == null || realmSettings == null) {
            return client;
        }
        final org.springframework.security.oauth2.server.authorization.settings.TokenSettings ts = client.getTokenSettings();
        final boolean access = Boolean.TRUE.equals(ts.getSetting(io.helixiam.authorization.domain.ServiceProviderOAuthClient.REALM_DEFAULT_ACCESS_TTL));
        final boolean refresh = Boolean.TRUE.equals(ts.getSetting(io.helixiam.authorization.domain.ServiceProviderOAuthClient.REALM_DEFAULT_REFRESH_TTL));
        if (!access && !refresh) {
            return client;
        }
        try {
            final io.helixiam.authorization.amqp.realm.RealmSettingsDto realm = realmSettings.get(RealmContextHolder.get());
            if (realm == null) {
                return client;
            }
            final org.springframework.security.oauth2.server.authorization.settings.TokenSettings.Builder b =
                    org.springframework.security.oauth2.server.authorization.settings.TokenSettings.withSettings(ts.getSettings());
            if (access && realm.accessTokenTtlSeconds() > 0) {
                b.accessTokenTimeToLive(java.time.Duration.ofSeconds(realm.accessTokenTtlSeconds()));
            }
            if (refresh && realm.refreshTokenTtlSeconds() > 0) {
                b.refreshTokenTimeToLive(java.time.Duration.ofSeconds(realm.refreshTokenTtlSeconds()));
            }
            return RegisteredClient.from(client).tokenSettings(b.build()).build();
        } catch (final RuntimeException e) {
            return client; // never block token issuance on a settings lookup
        }
    }
}
