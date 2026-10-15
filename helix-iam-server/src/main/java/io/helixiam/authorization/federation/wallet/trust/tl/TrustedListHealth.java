/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.wallet.trust.tl;

import java.time.Duration;
import java.time.Instant;

/**
 * The fail-safe rule, in one place: the last good list's anchors are used until its {@code NextUpdate} plus the
 * source's grace period, whatever later refreshes do (a list that cannot be fetched or verified does not replace
 * them); after that they are not used at all (fail closed) until a new list verifies.
 */
public final class TrustedListHealth {

    /** What a source's anchors are worth now. */
    public enum Status {
        /** Never loaded and no attempt yet. */
        NEVER,
        /** Never loaded successfully: the last attempt failed. No anchors. */
        ERROR,
        /** The last good list is before its NextUpdate and the last refresh succeeded. */
        OK,
        /** The last good list is before its NextUpdate, but the last refresh failed. Anchors still used. */
        FAILING,
        /** Past the last good list's NextUpdate, within the grace period. Anchors still used. */
        STALE,
        /** Past NextUpdate plus grace. No anchors (fail closed). */
        EXPIRED,
        /** The source is switched off. No anchors. */
        DISABLED,
        /**
         * A list of trusted lists that is itself fine, but some of whose members are failing, stale, expired or never
         * verified. The good members' anchors are used.
         */
        DEGRADED;

        /** Whether the last good anchors count in this status. */
        public boolean anchorsUsable() {
            return this == OK || this == FAILING || this == STALE || this == DEGRADED;
        }
    }

    private TrustedListHealth() {
    }

    /**
     * The status now.
     *
     * @param enabled           the source's switch
     * @param lastGoodNextUpdate the last good list's NextUpdate, or null when none was ever accepted
     * @param lastAttemptFailed whether the most recent refresh failed
     * @param attempted         whether any refresh ran
     */
    public static Status evaluate(final boolean enabled, final Instant lastGoodNextUpdate, final Duration grace,
                                  final boolean lastAttemptFailed, final boolean attempted, final Instant now) {
        if (!enabled) {
            return Status.DISABLED;
        }
        if (lastGoodNextUpdate == null) {
            return attempted ? Status.ERROR : Status.NEVER;
        }
        if (!now.isAfter(lastGoodNextUpdate)) {
            return lastAttemptFailed ? Status.FAILING : Status.OK;
        }
        return now.isAfter(lastGoodNextUpdate.plus(grace)) ? Status.EXPIRED : Status.STALE;
    }

    /** The status of a stored source now. */
    public static Status evaluate(final TrustedListSource source, final Instant now) {
        final TrustedListSource.State s = source.state();
        // a success clears last_error, a failure sets it: the most recent attempt failed exactly when it is set
        final boolean failed = s.lastError() != null;
        return evaluate(source.config().enabled(), s.servicesJson() == null || s.nextUpdate() == null ? null
                        : Instant.ofEpochMilli(s.nextUpdate()), Duration.ofHours(source.config().graceHours()), failed,
                s.lastAttemptAt() != null, now);
    }

    /** The status of one member of a list of trusted lists now (its own last good list, the source's grace). */
    public static Status evaluate(final TrustedListSource source, final TrustedListSource.Member m, final Instant now) {
        return evaluate(source.config().enabled(), m.servicesJson() == null || m.nextUpdate() == null ? null
                        : Instant.ofEpochMilli(m.nextUpdate()), Duration.ofHours(source.config().graceHours()),
                m.lastError() != null, m.lastAttemptAt() != null, now);
    }
}
