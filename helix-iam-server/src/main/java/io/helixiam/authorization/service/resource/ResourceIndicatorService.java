/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.service.resource;

import io.helixiam.authorization.repository.ServiceProviderRepository;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * Helix IAM (RFC 8707 — Resource Indicators). The realm-domain side of the per-client
 * <b>allowed resources</b> allow-list. The allow-list is stored on {@code service_provider_oauth} as a
 * comma/space-joined {@code allowed_resources} column (mirrors {@code web_origins}). An empty/blank
 * column means the client has no allow-list configured → any requested {@code resource} is accepted
 * (back-compat — pre-RFC-8707 clients are untouched).
 */
@Service
public class ResourceIndicatorService {

    private static final Logger LOG = LogManager.getLogger(ResourceIndicatorService.class);

    private final ServiceProviderRepository serviceProviders;

    public ResourceIndicatorService(final ServiceProviderRepository serviceProviders) {
        this.serviceProviders = serviceProviders;
    }

    /**
     * The configured allowed-resource allow-list for an OAuth client ({@code client_id} <b>within
     * {@code realmId}</b>). Returns an empty list when the client has none configured (accept any) or
     * cannot be resolved. Never throws — a lookup failure must not break token issuance. Realm-scoped
     * so a client id reused across realms resolves the right client.
     */
    @Transactional(readOnly = true)
    public List<String> resolveAllowedResourcesForClient(final String realmId, final String clientId) {
        try {
            return serviceProviders.findByClientIdAndRealmIdAndDeleted(clientId, realmId, false)
                    .map(c -> split(c.getAllowedResources()))
                    .orElseGet(Collections::emptyList);
        } catch (final Exception e) {
            LOG.warn("Allowed-resource resolution failed for client {}, treating as no allow-list: {}",
                    clientId, e.getMessage());
            return Collections.emptyList();
        }
    }

    /**
     * Set a client's allowed-resource allow-list (admin write, {@code client_id} <b>within {@code realmId}</b>).
     * Stores the ordered, de-duplicated list as the comma-joined column; an empty list clears the allow-list
     * (→ accept any resource). Returns {@code false} when the client does not exist.
     */
    @Transactional
    public boolean updateAllowedResources(final String realmId, final String clientId, final List<String> resources) {
        return serviceProviders.findByClientIdAndRealmIdAndDeleted(clientId, realmId, false).map(c -> {
            c.setAllowedResources(join(resources));
            serviceProviders.save(c);
            return true;
        }).orElse(false);
    }

    /** Join an ordered, de-duplicated list into the comma-stored column; empty → {@code null} (no allow-list). */
    private static String join(final List<String> values) {
        if (values == null || values.isEmpty()) {
            return null;
        }
        final Set<String> out = new LinkedHashSet<>();
        for (final String v : values) {
            if (v != null && !v.isBlank()) {
                out.add(v.trim());
            }
        }
        return out.isEmpty() ? null : String.join(",", out);
    }

    /** Split the comma/space-joined column into an ordered, de-duplicated list; blank → empty. */
    private static List<String> split(final String joined) {
        if (joined == null || joined.isBlank()) {
            return Collections.emptyList();
        }
        final Set<String> out = new LinkedHashSet<>();
        for (final String part : joined.split("[,\\s]+")) {
            if (!part.isBlank()) {
                out.add(part.trim());
            }
        }
        return List.copyOf(out);
    }
}
