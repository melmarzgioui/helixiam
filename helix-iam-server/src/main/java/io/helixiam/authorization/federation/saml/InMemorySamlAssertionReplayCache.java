/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.saml;


import java.time.Instant;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * Helix IAM E5.2 follow-up: default in-process {@link SamlAssertionReplayCache} (single-instance /
 * dev). Each entry expires at the assertion's {@code NotOnOrAfter}, and expired entries are pruned
 * lazily on access, so the map stays bounded by the count of assertions live within their window. A
 * Redis-backed cache replaces it for horizontal scale ({@code @ConditionalOnMissingBean}).
 */
public class InMemorySamlAssertionReplayCache implements SamlAssertionReplayCache {

    private final ConcurrentMap<String, Instant> seen = new ConcurrentHashMap<>();

    @Override
    public boolean checkAndRecord(final String assertionId, final Instant expiresAt) {
        final Instant now = Instant.now();
        // Prune anything whose window has already passed so the map cannot grow unbounded.
        seen.values().removeIf(expiry -> expiry.isBefore(now));

        if (expiresAt == null || !expiresAt.isAfter(now)) {
            // Already outside its window — nothing to protect against; don't retain it.
            return true;
        }
        return seen.putIfAbsent(assertionId, expiresAt) == null;
    }
}
