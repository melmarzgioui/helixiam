/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation;

import org.apache.logging.log4j.LogManager;

import java.io.Serializable;
import java.util.List;

/**
 * Final review F2: how a federated login that had to wait (a post-broker step-up, or MFA enrolment) ends, reported
 * to the connector that started it. A connector hands {@link FederatedLoginCompleter#completeLogin} an opaque,
 * serializable marker; while the login is pending the marker travels on the flow state in the session, and whoever
 * ends the login ({@code FlowController} after the step-up, the MFA enrolment completion) reports it here exactly once.
 * A login that completes or fails at once is reported by the connector itself, from the returned
 * {@link FederatedLoginCompleter.Completion}.
 *
 * <p>The EUDI wallet's login audit ({@code WalletLoginOutcomeAudit}) is the one implementation: its
 * {@code WALLET_LOGIN_SUCCESS} names the user the login finally signed in.
 */
public interface FederatedLoginOutcome {

    /** Whether this implementation knows {@code marker} (each connector its own markers). */
    boolean supports(Serializable marker);

    /** The login of {@code marker} completed for {@code userId}. */
    void completed(Serializable marker, String userId);

    /** The login of {@code marker} ended without a session (e.g. its pending commit was refused). */
    void failed(Serializable marker);

    /** Reports a completed login to the first of {@code outcomes} that supports {@code marker}. Never throws. */
    static void completed(final List<FederatedLoginOutcome> outcomes, final Serializable marker, final String userId) {
        report(outcomes, marker, outcome -> outcome.completed(marker, userId));
    }

    /** Reports a failed login to the first of {@code outcomes} that supports {@code marker}. Never throws. */
    static void failed(final List<FederatedLoginOutcome> outcomes, final Serializable marker) {
        report(outcomes, marker, outcome -> outcome.failed(marker));
    }

    private static void report(final List<FederatedLoginOutcome> outcomes, final Serializable marker,
                               final java.util.function.Consumer<FederatedLoginOutcome> call) {
        if (outcomes == null || marker == null) {
            return;
        }
        try {
            for (final FederatedLoginOutcome outcome : outcomes) {
                if (outcome.supports(marker)) {
                    call.accept(outcome);
                    return;
                }
            }
        } catch (final RuntimeException e) {
            // reporting must never undo or block a login that already ended
            LogManager.getLogger(FederatedLoginOutcome.class)
                    .warn("Federated login outcome could not be reported ({})", e.getClass().getSimpleName());
        }
    }
}
