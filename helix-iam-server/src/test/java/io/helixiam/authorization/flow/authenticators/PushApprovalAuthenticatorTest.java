/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.flow.authenticators;

import io.helixiam.authorization.flow.push.InMemoryPushApprovalStore;
import io.helixiam.authorization.flow.push.PushApprovalService;
import io.helixiam.authorization.flow.push.PushMessage;
import io.helixiam.authorization.flow.spi.AuthenticationContext;
import io.helixiam.authorization.flow.spi.FactorClass;
import org.junit.jupiter.api.Test;

import java.util.ArrayDeque;
import java.util.Deque;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Helix IAM E4.3: the push-approval factor sends "approve on your phone" with number matching for an
 * already-identified user (2nd factor / step-up), shows the match number, and on the browser's
 * post-back consumes the APPROVED request.
 */
class PushApprovalAuthenticatorTest {

    private final InMemoryPushApprovalStore store = new InMemoryPushApprovalStore();
    private final Deque<String> tokens = new ArrayDeque<>(java.util.List.of("push-1", "nonce-1"));
    private final Deque<Integer> numbers = new ArrayDeque<>(java.util.List.of(42, 13, 77));
    private final AtomicReference<PushMessage> sent = new AtomicReference<>();
    private final PushApprovalService service = new PushApprovalService(
            store, (t, u, i) -> true, sent::set, tokens::removeFirst, numbers::removeFirst, () -> 0L, 120_000L);
    private final PushApprovalAuthenticator authenticator = new PushApprovalAuthenticator(service);

    private AuthenticationContext context(final String userId) {
        return new AuthenticationContext("e-push", "master", userId);
    }

    @Test
    void metadata_isAPossessionFactorWithIdPush() {
        assertThat(authenticator.metadata().id()).isEqualTo("push");
        assertThat(authenticator.metadata().factorClass()).isEqualTo(FactorClass.POSSESSION);
    }

    @Test
    void authenticate_startsApprovalAndShowsTheMatchNumber() {
        final AuthenticationContext ctx = context("user-7");

        authenticator.authenticate(ctx);

        assertThat(ctx.status()).isEqualTo(AuthenticationContext.Status.CHALLENGE);
        assertThat(ctx.challengeView()).isEqualTo("push-form");
        assertThat(ctx.getAttribute("push.id")).isEqualTo("push-1");
        assertThat(ctx.getAttribute("push.number")).isEqualTo(42);
        assertThat(sent.get().expectedNumber()).isEqualTo(42);
    }

    @Test
    void authenticate_failsWhenNoUserIsIdentified() {
        final AuthenticationContext ctx = context(null);

        authenticator.authenticate(ctx);

        assertThat(ctx.status()).isEqualTo(AuthenticationContext.Status.FAILURE);
    }

    @Test
    void action_whenApproved_succeeds() {
        final AuthenticationContext ctx = context("user-7");
        authenticator.authenticate(ctx);
        service.approve("push-1", 42, "device-1", "c2ln"); // phone matches the number

        authenticator.action(ctx);

        assertThat(ctx.status()).isEqualTo(AuthenticationContext.Status.SUCCESS);
    }

    @Test
    void action_whenStillPending_reChallenges() {
        final AuthenticationContext ctx = context("user-7");
        authenticator.authenticate(ctx);

        authenticator.action(ctx);

        assertThat(ctx.status()).isEqualTo(AuthenticationContext.Status.CHALLENGE);
    }
}
