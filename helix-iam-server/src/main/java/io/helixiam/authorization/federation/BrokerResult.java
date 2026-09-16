/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation;

/**
 * Helix IAM E5.1: outcome of brokering an external identity to a local user.
 *
 * @param resolved    whether a local user was resolved at all (false = rejected: no match + JIT disabled)
 * @param userId      the local user id (null when not resolved)
 * @param provisioned whether a new local user was just-in-time created
 * @param linked      whether a new federated link was created this time (existing user or JIT)
 */
public record BrokerResult(boolean resolved, String userId, boolean provisioned, boolean linked) {

    public static BrokerResult unresolved() {
        return new BrokerResult(false, null, false, false);
    }

    public static BrokerResult existingLink(final String userId) {
        return new BrokerResult(true, userId, false, false);
    }

    public static BrokerResult linkedExisting(final String userId) {
        return new BrokerResult(true, userId, false, true);
    }

    public static BrokerResult provisioned(final String userId) {
        return new BrokerResult(true, userId, true, true);
    }
}
