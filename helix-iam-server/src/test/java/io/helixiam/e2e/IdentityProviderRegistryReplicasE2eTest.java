/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.e2e;

import io.helixiam.authorization.federation.FederationProviderFactory;
import io.helixiam.authorization.federation.FederationStoreRefresher;
import io.helixiam.authorization.federation.FederationStoreVersionPoller;
import io.helixiam.authorization.federation.IdentityProviderConfigSource;
import io.helixiam.authorization.federation.IdentityProviderRegistry;
import io.helixiam.authorization.federation.spi.IdpMetadata;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.BooleanSupplier;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Production readiness item 1: an identity-provider write or a realm import reaches every replica without a restart.
 * The booted server is replica A; the test runs a second replica B on the same database (its own registry, refresher
 * and version poller, polling every second), as a second pod would. A write handled by A bumps the realm's version in
 * {@code idp_config_version}, and B's poller picks it up within its interval. A realm import refreshes A at once and
 * bumps the version for B.
 */
class IdentityProviderRegistryReplicasE2eTest extends AbstractE2eTest {

    private static final Duration INTERVAL = Duration.ofSeconds(1);
    /** Within the interval, plus a generous margin for a loaded CI machine. */
    private static final Duration DEADLINE = INTERVAL.multipliedBy(8);

    private String realm;
    private E2eAdminSession admin;
    private IdentityProviderRegistry replicaB;
    private FederationStoreVersionPoller pollerB;

    @BeforeEach
    void setUp() {
        realm = E2eSeed.unique("replicas");
        seed().realm(realm);
        admin = adminSession();
        replicaB = new IdentityProviderRegistry(List.of());
        final FederationStoreRefresher refresherB = new FederationStoreRefresher(
                context.getBean(IdentityProviderConfigSource.class), context.getBean(FederationProviderFactory.class),
                replicaB);
        refresherB.refreshAll();
        pollerB = new FederationStoreVersionPoller(refresherB, INTERVAL);
        pollerB.start();
    }

    @AfterEach
    void tearDown() {
        pollerB.close();
    }

    @Test
    void aCreateUpdateAndDeleteOnReplicaA_reachReplicaB_withinThePollInterval() {
        assertThat(replicaB.aliases(realm)).isEmpty();

        final E2eHttp.Response created = admin.post(base(), body("upstream", "Upstream one"));
        assertThat(created.status()).as(created.toString()).isEqualTo(201);
        awaitOnB(() -> replicaB.aliases(realm).contains("upstream"), "the created provider");

        final E2eHttp.Response updated = admin.put(base() + "/upstream", body("upstream", "Upstream two"));
        assertThat(updated.status()).as(updated.toString()).isEqualTo(200);
        awaitOnB(() -> displayName("upstream").equals("Upstream two"), "the updated display name");

        assertThat(admin.delete(base() + "/upstream").status()).isEqualTo(204);
        awaitOnB(() -> !replicaB.aliases(realm).contains("upstream"), "the deletion");
    }

    @Test
    void aRealmImport_refreshesTheReplicaThatRanIt_atOnce_andReachesReplicaB() {
        final Map<String, Object> doc = new LinkedHashMap<>();
        doc.put("identityProviders", List.of(body("imported", "Imported")));

        final E2eHttp.Response imported = admin.post("/admin/realms/" + realm + "/import", doc);
        assertThat(imported.status()).as(imported.toString()).isEqualTo(200);
        assertThat(imported.json().path("slices").path("identityProviders").path("created").asInt())
                .as(imported.toString()).isEqualTo(1);

        assertThat(context.getBean(IdentityProviderRegistry.class).aliases(realm))
                .as("replica A, which ran the import, loads it without a restart").contains("imported");
        awaitOnB(() -> replicaB.aliases(realm).contains("imported"), "the imported provider");
    }

    // ------------------------------------------------------------------------------------------------ helpers

    private String displayName(final String alias) {
        return replicaB.metadatas(realm).stream().filter(m -> m.alias().equals(alias)).map(IdpMetadata::displayName)
                .findFirst().orElse("");
    }

    private static void awaitOnB(final BooleanSupplier condition, final String what) {
        final long deadline = System.nanoTime() + DEADLINE.toNanos();
        while (!condition.getAsBoolean()) {
            if (System.nanoTime() > deadline) {
                throw new AssertionError("replica B did not see " + what + " within " + DEADLINE);
            }
            try {
                Thread.sleep(50);
            } catch (final InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new AssertionError(e);
            }
        }
    }

    private String base() {
        return "/admin/realms/" + realm + "/identity-providers";
    }

    private static Map<String, Object> body(final String alias, final String displayName) {
        final Map<String, String> config = new LinkedHashMap<>();
        config.put("clientId", "helix");
        config.put("clientSecret", "replica-test-" + "secret");
        config.put("issuer", "https://upstream.example");
        config.put("authorizationEndpoint", "https://upstream.example/authorize");
        config.put("tokenEndpoint", "https://upstream.example/token");
        config.put("jwksUri", "https://upstream.example/jwks");
        final Map<String, Object> body = new LinkedHashMap<>();
        body.put("alias", alias);
        body.put("protocol", "oidc");
        body.put("displayName", displayName);
        body.put("enabled", true);
        body.put("config", config);
        return body;
    }
}
