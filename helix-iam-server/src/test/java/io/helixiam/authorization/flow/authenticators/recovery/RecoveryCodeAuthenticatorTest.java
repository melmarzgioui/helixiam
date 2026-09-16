package io.helixiam.authorization.flow.authenticators.recovery;

import io.helixiam.authorization.flow.spi.AuthenticationContext;
import io.helixiam.authorization.flow.spi.FactorClass;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Helix IAM E3.2: the recovery-code factor — a user enters one of their single-use backup codes,
 * which is verified and consumed via the {@link RecoveryCodeVerifier} seam (the live adapter
 * checks + burns the code in the store).
 */
class RecoveryCodeAuthenticatorTest {

    private AuthenticationContext context() {
        return new AuthenticationContext("e-recovery", "master", "user-1");
    }

    @Test
    void metadata_isAPossessionFactorWithIdRecoveryCode() {
        RecoveryCodeAuthenticator authenticator = new RecoveryCodeAuthenticator((u, c) -> true);

        assertThat(authenticator.metadata().id()).isEqualTo("recovery-code");
        assertThat(authenticator.metadata().factorClass()).isEqualTo(FactorClass.POSSESSION);
    }

    @Test
    void authenticate_promptsForACode() {
        RecoveryCodeAuthenticator authenticator = new RecoveryCodeAuthenticator((u, c) -> true);
        AuthenticationContext ctx = context();

        authenticator.authenticate(ctx);

        assertThat(ctx.status()).isEqualTo(AuthenticationContext.Status.CHALLENGE);
        assertThat(ctx.challengeView()).isEqualTo("recovery-code-form");
    }

    @Test
    void action_withAValidUnusedCode_succeeds() {
        RecoveryCodeAuthenticator authenticator =
                new RecoveryCodeAuthenticator((userId, code) -> userId.equals("user-1") && code.equals("ABCD-1234"));
        AuthenticationContext ctx = context();
        ctx.submit(Map.of("code", "ABCD-1234"));

        authenticator.action(ctx);

        assertThat(ctx.status()).isEqualTo(AuthenticationContext.Status.SUCCESS);
    }

    @Test
    void action_withAnInvalidOrUsedCode_fails() {
        RecoveryCodeAuthenticator authenticator = new RecoveryCodeAuthenticator((u, c) -> false);
        AuthenticationContext ctx = context();
        ctx.submit(Map.of("code", "WRONG-0000"));

        authenticator.action(ctx);

        assertThat(ctx.status()).isEqualTo(AuthenticationContext.Status.FAILURE);
    }

    @Test
    void action_withNoCode_fails() {
        RecoveryCodeAuthenticator authenticator = new RecoveryCodeAuthenticator((u, c) -> true);
        AuthenticationContext ctx = context();

        authenticator.action(ctx);

        assertThat(ctx.status()).isEqualTo(AuthenticationContext.Status.FAILURE);
    }
}
