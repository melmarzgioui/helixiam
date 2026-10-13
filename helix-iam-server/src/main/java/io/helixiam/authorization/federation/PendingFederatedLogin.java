/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation;

import io.helixiam.authorization.flow.FlowExecutionState;
import io.helixiam.authorization.security.flow.FlowLoginSuccessHandler;
import io.helixiam.authorization.security.session.AuthTimeStamper;
import io.helixiam.common.log.LogSafe;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.security.core.context.SecurityContextHolder;

import java.io.Serializable;
import java.util.List;

/**
 * The end of a login that had to wait on the user after its first factor — a post-login step-up ({@code /flow}) or
 * MFA enrolment ({@code /mfa/enable}) — once that user's full authentication has been restored. A federated login
 * left its connector's work on the login's {@link FlowExecutionState} ({@code FederatedLoginCompleter}); this does it,
 * in the one order every completion uses:
 * <ol>
 *   <li>the pending commit ({@link FederatedLoginCommit}), or undo the session when it is refused;</li>
 *   <li>{@link AuthTimeStamper#stamp} (which also clears any {@code acr} an earlier login left);</li>
 *   <li>the login's pending {@code acr};</li>
 *   <li>the connector's outcome ({@link FederatedLoginOutcome}), exactly once;</li>
 *   <li>the flow state leaves the session, so nothing of this login can be completed again.</li>
 * </ol>
 * A password login's state carries none of this and only gets the stamp and the clean-up.
 */
public final class PendingFederatedLogin {

    private static final Logger LOG = LogManager.getLogger(PendingFederatedLogin.class);

    private PendingFederatedLogin() {
    }

    /** The session's login flow state when it is {@code userId}'s; {@code null} when absent or another user's. */
    public static FlowExecutionState of(final HttpSession session, final String userId) {
        if (session == null || userId == null) {
            return null;
        }
        final Object value = session.getAttribute(FlowLoginSuccessHandler.FLOW_STATE_ATTRIBUTE);
        return value instanceof FlowExecutionState state && userId.equals(state.userId()) ? state : null;
    }

    /** Removes the login flow state (and its definition) from the session: a login's work is done or abandoned. */
    public static void clear(final HttpSession session) {
        if (session != null) {
            session.removeAttribute(FlowLoginSuccessHandler.FLOW_STATE_ATTRIBUTE);
            session.removeAttribute(FlowLoginSuccessHandler.FLOW_DEFINITION_ATTRIBUTE);
        }
    }

    /**
     * Ends {@code state}'s login for its user, whose full authentication the caller has just restored. {@code state} may
     * be {@code null} (a login without a flow state): then only the stamp is made.
     *
     * @return {@code true} when the login stands; {@code false} when its pending commit was refused: the context is
     *         cleared, the session invalidated and the connector told the login failed
     */
    public static boolean finish(final HttpServletRequest request, final FlowExecutionState state,
                                 final List<FederatedLoginCommit> commits, final List<FederatedLoginOutcome> outcomes,
                                 final AuthTimeStamper stamper) {
        if (state != null && state.pendingCommit() != null
                && !FederatedLoginCommit.commit(commits, state.pendingCommit(), state.userId())) {
            // Task 18: committed only once the session is fully signed in; refused → drop that session (context and
            // session) so the login does not stay signed in.
            SecurityContextHolder.clearContext();
            final HttpSession session = request.getSession(false);
            if (session != null) {
                session.invalidate();
            }
            report(state, outcomes, false);
            LOG.warn("Login for user {} refused: its pending commit was not accepted",
                    LogSafe.sanitize(state.userId()));
            return false;
        }
        stamper.stamp(request); // SSO P2 — also clears any stale acr from an earlier login
        final HttpSession session = request.getSession();
        if (state != null && state.pendingAcr() != null && !state.pendingAcr().isBlank()) {
            // Task 3 fix round 1: THIS login's acr, only now that it completed and AFTER stamp() cleared any stale
            // value — never earlier, so an abandoned step-up can never leak into an unrelated login.
            session.setAttribute(AuthTimeStamper.ACR_SESSION_ATTRIBUTE, state.pendingAcr());
        }
        if (state != null) {
            report(state, outcomes, true);
        }
        clear(session);
        return true;
    }

    /** Final review F2: the connector's outcome, once (the marker is cleared). */
    private static void report(final FlowExecutionState state, final List<FederatedLoginOutcome> outcomes,
                               final boolean completed) {
        final Serializable marker = state.pendingOutcome();
        state.setPendingOutcome(null);
        if (completed) {
            FederatedLoginOutcome.completed(outcomes, marker, state.userId());
        } else {
            FederatedLoginOutcome.failed(outcomes, marker);
        }
    }
}
