package io.helixiam.authorization.flow.authenticators;

import io.helixiam.authorization.flow.spi.AuthenticationContext;
import io.helixiam.authorization.flow.spi.FactorClass;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Helix IAM E3.4: HOTP factor — verifies the submitted code via the generic
 * {@link CredentialVerifier} using credential type "hotp".
 */
class HotpAuthenticatorTest {

    private AuthenticationContext context() {
        return new AuthenticationContext("e-hotp", "master", "user-1");
    }

    @Test
    void metadata_isAPossessionFactorWithIdHotp() {
        HotpAuthenticator authenticator = new HotpAuthenticator((t, u, i) -> true);

        assertThat(authenticator.metadata().id()).isEqualTo("hotp");
        assertThat(authenticator.metadata().factorClass()).isEqualTo(FactorClass.POSSESSION);
    }

    @Test
    void authenticate_promptsForTheCode() {
        HotpAuthenticator authenticator = new HotpAuthenticator((t, u, i) -> true);
        AuthenticationContext ctx = context();

        authenticator.authenticate(ctx);

        assertThat(ctx.status()).isEqualTo(AuthenticationContext.Status.CHALLENGE);
        assertThat(ctx.challengeView()).isEqualTo("otp-form");
    }

    @Test
    void action_verifiesViaTheHotpCredentialType() {
        HotpAuthenticator authenticator = new HotpAuthenticator(
                (type, userId, input) -> type.equals("hotp") && userId.equals("user-1") && input.equals("755224"));
        AuthenticationContext ctx = context();
        ctx.submit(Map.of("code", "755224"));

        authenticator.action(ctx);

        assertThat(ctx.status()).isEqualTo(AuthenticationContext.Status.SUCCESS);
    }

    @Test
    void action_wrongCode_fails() {
        HotpAuthenticator authenticator = new HotpAuthenticator((t, u, i) -> false);
        AuthenticationContext ctx = context();
        ctx.submit(Map.of("code", "000000"));

        authenticator.action(ctx);

        assertThat(ctx.status()).isEqualTo(AuthenticationContext.Status.FAILURE);
    }
}
