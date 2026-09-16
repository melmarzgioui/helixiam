package io.helixiam.authorization.flow.authenticators;

import io.helixiam.authorization.flow.spi.AuthenticationContext;
import io.helixiam.authorization.flow.spi.FactorClass;
import org.junit.jupiter.api.Test;

import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Helix IAM E4.1: the VeridPay-style device factor — issues a single-use server challenge, renders
 * the device-approval view, then packs the device assertion (deviceId + challenge + ES256 signature)
 * and verifies it via the generic {@link CredentialVerifier} under credential type "device".
 */
class DeviceAuthenticatorTest {

    private DeviceAuthenticator authenticator(final CredentialVerifier verifier) {
        return new DeviceAuthenticator(verifier);
    }

    private AuthenticationContext context() {
        return new AuthenticationContext("e-device", "master", "user-1");
    }

    @Test
    void metadata_isAPossessionFactorWithIdDevice() {
        assertThat(authenticator((t, u, i) -> true).metadata().id()).isEqualTo("device");
        assertThat(authenticator((t, u, i) -> true).metadata().factorClass()).isEqualTo(FactorClass.POSSESSION);
    }

    @Test
    void authenticate_issuesAChallenge_andRendersTheForm() {
        final DeviceAuthenticator authenticator = authenticator((t, u, i) -> true);
        final AuthenticationContext ctx = context();

        authenticator.authenticate(ctx);

        assertThat(ctx.status()).isEqualTo(AuthenticationContext.Status.CHALLENGE);
        assertThat(ctx.challengeView()).isEqualTo("device-form");
        assertThat(ctx.getAttribute("device.challenge")).isNotNull();
    }

    @Test
    void action_packsTheAssertionWithChallengeAndVerifiesUnderDeviceType() {
        final AtomicReference<String> sentType = new AtomicReference<>();
        final AtomicReference<String> sentInput = new AtomicReference<>();
        final CredentialVerifier capturing = (type, userId, input) -> {
            sentType.set(type);
            sentInput.set(input);
            return true;
        };
        final DeviceAuthenticator authenticator = authenticator(capturing);
        final AuthenticationContext ctx = context();
        authenticator.authenticate(ctx);
        ctx.submit(Map.of("deviceId", "device-1", "signature", "ZGVyc2ln"));

        authenticator.action(ctx);

        assertThat(ctx.status()).isEqualTo(AuthenticationContext.Status.SUCCESS);
        assertThat(sentType.get()).isEqualTo("device");
        assertThat(sentInput.get()).contains("device-1").contains("challenge").contains("signature");
    }

    @Test
    void action_missingAssertion_fails() {
        final DeviceAuthenticator authenticator = authenticator((t, u, i) -> true);
        final AuthenticationContext ctx = context();
        authenticator.authenticate(ctx);
        ctx.submit(Map.of()); // no deviceId/signature

        authenticator.action(ctx);

        assertThat(ctx.status()).isEqualTo(AuthenticationContext.Status.FAILURE);
    }

    @Test
    void action_verificationFails_fails() {
        final DeviceAuthenticator authenticator = authenticator((t, u, i) -> false);
        final AuthenticationContext ctx = context();
        authenticator.authenticate(ctx);
        ctx.submit(Map.of("deviceId", "device-1", "signature", "ZGVyc2ln"));

        authenticator.action(ctx);

        assertThat(ctx.status()).isEqualTo(AuthenticationContext.Status.FAILURE);
    }
}
