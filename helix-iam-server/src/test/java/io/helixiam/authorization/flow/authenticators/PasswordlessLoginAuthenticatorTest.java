/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.flow.authenticators;

import io.helixiam.authorization.flow.spi.AuthenticationContext;
import io.helixiam.authorization.flow.spi.FactorClass;
import org.junit.jupiter.api.Test;

import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Helix IAM (10): the passwordless, usernameless passkey login authenticator — an identity-establishing
 * FIRST step. It issues a server challenge, renders the conditional-UI passkey page, then packs the resident-
 * key assertion and asks the {@link ResidentKeyResolver} to resolve+verify it. On success it establishes the
 * resolved user on the context (no username typed); on failure it fails closed.
 */
class PasswordlessLoginAuthenticatorTest {

    private PasswordlessLoginAuthenticator authenticator(final ResidentKeyResolver resolver) {
        return new PasswordlessLoginAuthenticator(resolver, "localhost", "http://localhost:8083");
    }

    /** A first-step context has no user yet — exactly the usernameless case. */
    private AuthenticationContext context() {
        return new AuthenticationContext("e-passkey", "master", null);
    }

    @Test
    void metadata_isAPossessionFactorWithIdPasskeyLogin() {
        var a = authenticator(input -> Optional.of("u1"));
        assertThat(a.metadata().id()).isEqualTo("passkey-login");
        assertThat(a.metadata().factorClass()).isEqualTo(FactorClass.POSSESSION);
    }

    @Test
    void authenticate_issuesAChallenge_andRendersTheConditionalUiForm() {
        PasswordlessLoginAuthenticator a = authenticator(input -> Optional.of("u1"));
        AuthenticationContext ctx = context();

        a.authenticate(ctx);

        assertThat(ctx.status()).isEqualTo(AuthenticationContext.Status.CHALLENGE);
        assertThat(ctx.challengeView()).isEqualTo("passkey-login-form");
        assertThat(ctx.getAttribute("passkey-login.challenge")).isNotNull();
    }

    @Test
    void action_resolvesTheUserFromTheResidentKey_andEstablishesIt() {
        AtomicReference<String> sentInput = new AtomicReference<>();
        ResidentKeyResolver resolver = input -> {
            sentInput.set(input);
            return Optional.of("user-from-passkey");
        };
        PasswordlessLoginAuthenticator a = authenticator(resolver);
        AuthenticationContext ctx = context();
        a.authenticate(ctx); // issues + stashes the challenge
        ctx.submit(Map.of("credentialId", "cred-123", "userHandle", "uh",
                "authenticatorData", "ad", "clientDataJSON", "cdj", "signature", "sig"));

        a.action(ctx);

        assertThat(ctx.status()).isEqualTo(AuthenticationContext.Status.SUCCESS);
        // Identity established from the discoverable credential — no username was ever supplied.
        assertThat(ctx.userId()).isEqualTo("user-from-passkey");
        assertThat(sentInput.get()).contains("cred-123").contains("rpId").contains("challenge").contains("userHandle");
    }

    @Test
    void action_unknownOrInvalidPasskey_failsClosed_andEstablishesNoUser() {
        PasswordlessLoginAuthenticator a = authenticator(input -> Optional.empty());
        AuthenticationContext ctx = context();
        a.authenticate(ctx);
        ctx.submit(Map.of("credentialId", "cred-x", "authenticatorData", "ad",
                "clientDataJSON", "cdj", "signature", "sig"));

        a.action(ctx);

        assertThat(ctx.status()).isEqualTo(AuthenticationContext.Status.FAILURE);
        assertThat(ctx.userId()).isNull();
    }

    @Test
    void action_withNoCredentialPresented_fails_withoutCallingTheResolver() {
        AtomicReference<Boolean> called = new AtomicReference<>(false);
        ResidentKeyResolver resolver = input -> {
            called.set(true);
            return Optional.of("u1");
        };
        PasswordlessLoginAuthenticator a = authenticator(resolver);
        AuthenticationContext ctx = context();
        a.authenticate(ctx);
        // No credentialId submitted (user dismissed the passkey prompt).
        ctx.submit(Map.of("authenticatorData", "ad"));

        a.action(ctx);

        assertThat(ctx.status()).isEqualTo(AuthenticationContext.Status.FAILURE);
        assertThat(called.get()).isFalse();
    }
}
