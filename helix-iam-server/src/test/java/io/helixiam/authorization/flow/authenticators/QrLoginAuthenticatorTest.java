/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.flow.authenticators;

import io.helixiam.authorization.flow.qr.InMemoryQrSessionStore;
import io.helixiam.authorization.flow.qr.QrLoginService;
import io.helixiam.authorization.flow.spi.AuthenticationContext;
import io.helixiam.authorization.flow.spi.FactorClass;
import org.junit.jupiter.api.Test;

import java.util.ArrayDeque;
import java.util.Deque;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Helix IAM E4.2: the QR-login factor opens a cross-device session, renders the QR view, and on the
 * browser's post-back consumes a CONFIRMED session to establish the user (passwordless 1st factor).
 */
class QrLoginAuthenticatorTest {

    private final InMemoryQrSessionStore store = new InMemoryQrSessionStore();
    private final Deque<String> tokens = new ArrayDeque<>(java.util.List.of("sess-1", "tok-1"));
    private final QrLoginService service =
            new QrLoginService(store, (t, u, i) -> true, tokens::removeFirst, () -> 0L, 300_000L, 30_000L);
    private final QrLoginAuthenticator authenticator = new QrLoginAuthenticator(service);

    private AuthenticationContext context() {
        return new AuthenticationContext("e-qr", "master", null);
    }

    @Test
    void metadata_isAPossessionFactorWithIdQrLogin() {
        assertThat(authenticator.metadata().id()).isEqualTo("qr-login");
        assertThat(authenticator.metadata().factorClass()).isEqualTo(FactorClass.POSSESSION);
    }

    @Test
    void authenticate_opensASessionAndRendersTheQrView() {
        final AuthenticationContext ctx = context();

        authenticator.authenticate(ctx);

        assertThat(ctx.status()).isEqualTo(AuthenticationContext.Status.CHALLENGE);
        assertThat(ctx.challengeView()).isEqualTo("qr-login-form");
        assertThat(ctx.getAttribute("qr.session")).isEqualTo("sess-1");
        assertThat(ctx.getAttribute("qr.token")).isEqualTo("tok-1");
    }

    @Test
    void action_whenConfirmed_establishesUserAndSucceeds() {
        final AuthenticationContext ctx = context();
        authenticator.authenticate(ctx);                                  // opens sess-1 / tok-1
        service.confirm("sess-1", "tok-1", "user-7", "device-1", "c2ln"); // phone confirms

        authenticator.action(ctx);

        assertThat(ctx.status()).isEqualTo(AuthenticationContext.Status.SUCCESS);
        assertThat(ctx.userId()).isEqualTo("user-7");
    }

    @Test
    void action_whenStillPending_reChallengesToKeepWaiting() {
        final AuthenticationContext ctx = context();
        authenticator.authenticate(ctx);

        authenticator.action(ctx); // browser polled too early / no confirm yet

        assertThat(ctx.status()).isEqualTo(AuthenticationContext.Status.CHALLENGE);
        assertThat(ctx.userId()).isNull();
    }

    @Test
    void action_missingSession_fails() {
        final AuthenticationContext ctx = context();
        authenticator.action(ctx); // no authenticate() first

        assertThat(ctx.status()).isEqualTo(AuthenticationContext.Status.FAILURE);
    }
}
