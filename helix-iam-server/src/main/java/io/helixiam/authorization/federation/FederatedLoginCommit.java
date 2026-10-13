/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation;

import java.io.Serializable;

/**
 * Task 18: work a federated login may only do once it has fully succeeded. A connector hands
 * {@link FederatedLoginCompleter#complete(String, String, jakarta.servlet.http.HttpServletRequest,
 * jakarta.servlet.http.HttpServletResponse, Serializable)} an opaque pending value; the completer (or, after a step-up,
 * {@code FlowController}) calls {@link #commit} when the post-broker flow has COMPLETED and the full session has been
 * established. A {@code false} refuses the login: the session is dropped again and the browser is sent back to the
 * login page.
 *
 * <p>Any number of implementations may exist ({@link #commit(java.util.List, Serializable, String)}): the first one
 * that {@link #supports} the pending value makes the commit; a value none supports refuses the login.
 *
 * <p>The EUDI wallet's upgrade link ({@code WalletPendingLinkCommit}) is the one implementation: a weak attribute-tuple
 * match must never become a permanent administrative-number link for a login that then fails a step-up.
 */
public interface FederatedLoginCommit {

    /** Whether this committer knows {@code pending} (each connector its own pending values). */
    boolean supports(Serializable pending);

    /**
     * Makes the pending commit for {@code userId}, the user about to be signed in.
     *
     * @return whether the login may complete; {@code false} for a value this committer does not understand
     */
    boolean commit(Serializable pending, String userId);

    /**
     * Commits {@code pending} for {@code userId} with the first of {@code commits} that supports it. Never throws: a
     * committer that fails (e.g. its database or RPC) refuses the login exactly like a {@code false}, because the
     * callers have already established the session and must undo it (only the exception type is logged).
     *
     * @return whether the login may complete; {@code false} when none supports the value or the commit failed
     */
    static boolean commit(final java.util.List<FederatedLoginCommit> commits, final Serializable pending,
                          final String userId) {
        if (commits == null) {
            return false;
        }
        try {
            for (final FederatedLoginCommit commit : commits) {
                if (commit.supports(pending)) {
                    return commit.commit(pending, userId);
                }
            }
        } catch (final RuntimeException e) {
            org.apache.logging.log4j.LogManager.getLogger(FederatedLoginCommit.class)
                    .warn("Federated login refused: its pending commit failed ({})", e.getClass().getSimpleName());
        }
        return false;
    }
}
