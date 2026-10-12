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
 * {@code FlowController}) calls {@link #commit} when the post-broker flow has COMPLETED, right before the full session
 * is established. A {@code false} refuses the login: no session is established and the browser is sent back to the
 * login page.
 *
 * <p>The EUDI wallet's upgrade link ({@code WalletPendingLinkCommit}) is the one implementation: a weak attribute-tuple
 * match must never become a permanent administrative-number link for a login that then fails a step-up.
 */
public interface FederatedLoginCommit {

    /**
     * Makes the pending commit for {@code userId}, the user about to be signed in.
     *
     * @return whether the login may complete; {@code false} for a value this committer does not understand
     */
    boolean commit(Serializable pending, String userId);
}
