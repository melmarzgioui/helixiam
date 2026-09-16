/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.controller.admin;

import io.helixiam.authorization.amqp.application.ApplicationConfigPublisher;
import io.helixiam.authorization.amqp.client.ClientAdminPublisher;
import io.helixiam.authorization.amqp.federation.IdentityProviderConfigPublisher;
import io.helixiam.authorization.amqp.saml.SamlRelyingPartyConfigPublisher;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Helix IAM (E8.6): a live health snapshot for the admin console's Health screen. The publisher (auth edge)
 * owns no datasource, so it probes the platform by round-tripping the existing AMQP admin publishers — a
 * successful list call proves the message queue, the identity-domain subscriber, and its database are all
 * alive in one shot. Returns per-component status + a few realm counts, degrading gracefully on any failure.
 */
@RestController
@RequestMapping("/admin/realms/{realmId}/health")
public class HealthAdminController {

    private final ApplicationConfigPublisher applications;
    private final ClientAdminPublisher clients;
    private final SamlRelyingPartyConfigPublisher samlRelyingParties;
    private final IdentityProviderConfigPublisher identityProviders;

    public HealthAdminController(final ApplicationConfigPublisher applications,
                                final ClientAdminPublisher clients,
                                final SamlRelyingPartyConfigPublisher samlRelyingParties,
                                final IdentityProviderConfigPublisher identityProviders) {
        this.applications = applications;
        this.clients = clients;
        this.samlRelyingParties = samlRelyingParties;
        this.identityProviders = identityProviders;
    }

    /** Component health + counts. Each count is a fresh AMQP round-trip, so it also re-asserts liveness. */
    public record Component(String name, String status, String detail) {
    }

    public record HealthSnapshot(String overall, List<Component> components, Map<String, Integer> counts,
                                 String checkedAt) {
    }

    @GetMapping
    public HealthSnapshot health(@PathVariable final String realmId) {
        final List<Component> components = new ArrayList<>();
        final Map<String, Integer> counts = new LinkedHashMap<>();

        // The auth edge is up by definition — we are answering this request.
        components.add(new Component("Auth edge (OAuth/OIDC server)", "up", "Serving admin + token endpoints"));

        // One probe call proves the queue + identity domain + database in a single round-trip.
        boolean domainUp = true;
        String domainDetail = "Reachable over the message queue";
        try {
            counts.put("applications", applications.list(realmId).size());
        } catch (final RuntimeException e) {
            domainUp = false;
            domainDetail = "Probe failed: " + shortMessage(e);
        }
        final String domainStatus = domainUp ? "up" : "down";
        components.add(new Component("Message queue (AMQP)", domainStatus,
                domainUp ? "Round-trip OK" : "No response — " + domainDetail));
        components.add(new Component("Identity domain (state owner)", domainStatus, domainDetail));
        components.add(new Component("Database (PostgreSQL)", domainStatus,
                domainUp ? "Reads succeeding" : "Unreachable via the identity domain"));

        // The remaining counts are best-effort — a single failure shouldn't blank the whole page.
        if (domainUp) {
            countQuietly(counts, "oidcClients", () -> clients.list(realmId).size());
            countQuietly(counts, "samlRelyingParties", () -> samlRelyingParties.list(realmId).size());
            countQuietly(counts, "identityProviders", () -> identityProviders.list(realmId).size());
        }

        final String overall = domainUp ? "healthy" : "degraded";
        return new HealthSnapshot(overall, components, counts, Instant.now().toString());
    }

    private static void countQuietly(final Map<String, Integer> counts, final String key,
                                     final java.util.function.IntSupplier supplier) {
        try {
            counts.put(key, supplier.getAsInt());
        } catch (final RuntimeException ignored) {
            // Leave the key absent; the console shows "—" for a count it can't read.
        }
    }

    private static String shortMessage(final Throwable t) {
        final String m = t.getMessage();
        return m == null ? t.getClass().getSimpleName() : (m.length() > 120 ? m.substring(0, 120) + "…" : m);
    }
}
