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

        if (expiresAt == null) {
            // Fail closed: with no usable expiry we cannot guarantee one-time use, so treat it as
            // already-seen (reject). Callers must reject an assertion that lacks an enforceable expiry
            // upstream (see OpenSamlAssertionValidator.verifyConditions), so this is defense in depth.
            return false;
        }
        if (!expiresAt.isAfter(now)) {
            // Already outside its window — the validity-window check rejects it upstream; nothing to retain.
            return true;
        }
        return seen.putIfAbsent(assertionId, expiresAt) == null;
    }
}
