/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation;

import io.helixiam.authorization.flow.FlowExecutionState;
import io.helixiam.authorization.security.session.AuthTimeStamper;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;

import java.io.Serializable;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * The session is already signed in when the pending commit runs. A committer that throws an {@link Error} (out of
 * memory, a stack overflow, a linkage error) must not leave it so: the session is invalidated and the context cleared,
 * the connector is told the login failed, and only then does the {@code Error} propagate.
 */
class PendingFederatedLoginErrorTest {

    private static final Serializable PENDING = "pending-link";

    @AfterEach
    void clear() {
        SecurityContextHolder.clearContext();
    }

    private static FederatedLoginCommit throwing(final Throwable t) {
        return new FederatedLoginCommit() {
            @Override
            public boolean supports(final Serializable pending) {
                return true;
            }

            @Override
            public boolean commit(final Serializable pending, final String userId) {
                if (t instanceof Error e) {
                    throw e;
                }
                throw (RuntimeException) t;
            }
        };
    }

    private static MockHttpServletRequest signedIn(final MockHttpSession session) {
        SecurityContextHolder.getContext().setAuthentication(
                UsernamePasswordAuthenticationToken.authenticated("ada", null, List.of()));
        final MockHttpServletRequest request = new MockHttpServletRequest();
        request.setSession(session);
        return request;
    }

    private static FlowExecutionState state() {
        final FlowExecutionState state = new FlowExecutionState("gov");
        state.setUserId("ada");
        state.setPendingCommit(PENDING);
        state.setPendingOutcome("marker");
        return state;
    }

    @Test
    void anErrorFromTheCommit_invalidatesTheSession_clearsTheContext_reportsTheFailure_thenPropagates() {
        final MockHttpSession session = new MockHttpSession();
        final MockHttpServletRequest request = signedIn(session);
        final List<Boolean> reported = new java.util.ArrayList<>();
        final FederatedLoginOutcome outcome = new FederatedLoginOutcome() {
            @Override
            public boolean supports(final Serializable marker) {
                return true;
            }

            @Override
            public void completed(final Serializable marker, final String userId) {
                reported.add(true);
            }

            @Override
            public void failed(final Serializable marker) {
                reported.add(false);
            }
        };
        final StackOverflowError error = new StackOverflowError("boom");

        assertThatThrownBy(() -> PendingFederatedLogin.finish(request, state(), List.of(throwing(error)),
                List.of(outcome), new AuthTimeStamper())).isSameAs(error);

        assertThat(session.isInvalid()).as("the signed-in session is dropped").isTrue();
        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
        assertThat(reported).containsExactly(false);
    }

    @Test
    void aRuntimeExceptionFromTheCommit_stillRefusesTheLogin_withoutPropagating() {
        final MockHttpSession session = new MockHttpSession();

        final boolean stands = PendingFederatedLogin.finish(signedIn(session), state(),
                List.of(throwing(new IllegalStateException("db down"))), List.of(), new AuthTimeStamper());

        assertThat(stands).isFalse();
        assertThat(session.isInvalid()).isTrue();
        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
    }
}
