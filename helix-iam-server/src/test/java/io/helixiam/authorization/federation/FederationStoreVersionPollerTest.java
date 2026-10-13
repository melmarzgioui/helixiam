/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation;

import io.helixiam.authorization.amqp.federation.IdentityProviderConfig;
import io.helixiam.authorization.federation.eid.EidAssertionValidator;
import io.helixiam.authorization.federation.oidc.OidcTokenClient;
import io.helixiam.authorization.federation.saml.SamlAssertionValidator;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

/**
 * Production readiness item 1: the poller reloads, on its own schedule, the realms another replica wrote, and a poll
 * that fails (the database away) never throws out of the scheduler.
 */
class FederationStoreVersionPollerTest {

    private final FederationProviderFactory factory = new FederationProviderFactory(
            mock(OidcTokenClient.class), mock(SamlAssertionValidator.class), mock(EidAssertionValidator.class),
            mock(io.helixiam.authorization.federation.eid.EidArtifactResolver.class),
            mock(io.helixiam.authorization.federation.wallet.WalletIdentityProviders.class));

    private final Map<String, List<IdentityProviderConfig>> configs = new ConcurrentHashMap<>();
    private final Map<String, Long> versions = new ConcurrentHashMap<>();
    private volatile boolean databaseDown;

    private final IdentityProviderConfigSource store = new IdentityProviderConfigSource() {
        @Override
        public List<IdentityProviderConfig> load(final String realmId) {
            return configs.getOrDefault(realmId, List.of());
        }

        @Override
        public List<IdentityProviderConfig> loadAll() {
            return configs.values().stream().flatMap(List::stream).toList();
        }

        @Override
        public Map<String, Long> versions() {
            if (databaseDown) {
                throw new IllegalStateException("connection refused");
            }
            return Map.copyOf(versions);
        }
    };

    private static IdentityProviderConfig oidc(final String realm, final String alias) {
        return new IdentityProviderConfig(realm, alias, "oidc", alias, true,
                Map.of("clientId", "cid", "clientSecret", "sec",
                        "authorizationEndpoint", "https://idp/authorize", "tokenEndpoint", "https://idp/token",
                        "jwksUri", "https://idp/jwks", "issuer", "https://idp", "scopes", "openid"));
    }

    @Test
    void aWriteOnAnotherReplica_isLoadedWithinTheInterval() throws InterruptedException {
        final IdentityProviderRegistry registry = new IdentityProviderRegistry(List.of());
        try (FederationStoreVersionPoller poller = new FederationStoreVersionPoller(
                new FederationStoreRefresher(store, factory, registry), Duration.ofMillis(50))) {
            poller.start();

            configs.put("gov", List.of(oidc("gov", "corp")));
            versions.put("gov", 1L);

            final long deadline = System.nanoTime() + Duration.ofSeconds(5).toNanos();
            while (!registry.aliases("gov").contains("corp") && System.nanoTime() < deadline) {
                Thread.sleep(20);
            }
            assertThat(registry.aliases("gov")).containsExactly("corp");
        }
    }

    @Test
    void aFailingPoll_neverThrows_andTheNextOneCatchesUp() {
        final IdentityProviderRegistry registry = new IdentityProviderRegistry(List.of());
        final FederationStoreVersionPoller poller = new FederationStoreVersionPoller(
                new FederationStoreRefresher(store, factory, registry), Duration.ofSeconds(10));
        configs.put("gov", List.of(oidc("gov", "corp")));
        versions.put("gov", 1L);
        databaseDown = true;

        assertThat(poller.pollOnce()).isZero();

        databaseDown = false;
        assertThat(poller.pollOnce()).isEqualTo(1);
        assertThat(registry.aliases("gov")).containsExactly("corp");
    }

    @Test
    void aZeroInterval_turnsPollingOff() {
        final FederationStoreVersionPoller poller = new FederationStoreVersionPoller(
                new FederationStoreRefresher(store, factory, new IdentityProviderRegistry(List.of())), Duration.ZERO);
        poller.start(); // no scheduler, nothing to close
        poller.close();
    }
}
