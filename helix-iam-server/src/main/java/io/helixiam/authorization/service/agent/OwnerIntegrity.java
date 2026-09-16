/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.service.agent;

import java.util.Collection;

/**
 * Owner integrity for agents (NHIs). An agent's {@code owner} names the accountable human; this classifies
 * whether that human is a real, live user of the realm, so the two dangerous states surface for review:
 * <ul>
 *   <li>{@link OwnerStatus#UNKNOWN} — the owner string matches no user in the realm (a fictional owner).</li>
 *   <li>{@link OwnerStatus#ORPHANED} — it matches a user who is now disabled/deprovisioned (a "zombie owner":
 *       the agent looks governed but nobody is actually accountable).</li>
 *   <li>{@link OwnerStatus#VALID} — it matches an enabled realm user.</li>
 * </ul>
 * Pure and side-effect-free: the caller supplies the realm's users. Matching is on username OR email,
 * case- and whitespace-insensitive (usernames/emails are stored lowercase).
 */
public final class OwnerIntegrity {

    public enum OwnerStatus { VALID, UNKNOWN, ORPHANED }

    /** A realm user reduced to what owner classification needs. */
    public record RealmUser(String username, String email, boolean enabled) {}

    private OwnerIntegrity() {
    }

    public static OwnerStatus classify(final String owner, final Collection<RealmUser> realmUsers) {
        final String key = norm(owner);
        if (key.isEmpty()) {
            return OwnerStatus.UNKNOWN;
        }
        for (final RealmUser u : realmUsers) {
            if (key.equals(norm(u.username())) || key.equals(norm(u.email()))) {
                return u.enabled() ? OwnerStatus.VALID : OwnerStatus.ORPHANED;
            }
        }
        return OwnerStatus.UNKNOWN;
    }

    private static String norm(final String s) {
        return s == null ? "" : s.trim().toLowerCase();
    }
}
