package io.helixiam.authorization.flow.authenticators;

import io.helixiam.authorization.flow.spi.AuthenticationContext;
import io.helixiam.authorization.flow.spi.FactorClass;
import org.junit.jupiter.api.Test;

import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Helix IAM E3.3: the WebAuthn/passkey factor — issues a server challenge, renders the page that
 * drives navigator.credentials.get(), then packs the browser assertion + challenge and verifies
 * it via the generic {@link CredentialVerifier} under credential type "webauthn".
 */
class WebAuthnAuthenticatorTest {

    private WebAuthnAuthenticator authenticator(final CredentialVerifier verifier) {
        return new WebAuthnAuthenticator(verifier, "localhost", "http://localhost:8083");
    }

    private AuthenticationContext context() {
        return new AuthenticationContext("e-webauthn", "master", "user-1");
    }

    @Test
    void metadata_isAPossessionFactorWithIdWebauthn() {
        assertThat(authenticator((t, u, i) -> true).metadata().id()).isEqualTo("webauthn");
        assertThat(authenticator((t, u, i) -> true).metadata().factorClass()).isEqualTo(FactorClass.POSSESSION);
    }

    @Test
    void authenticate_issuesAChallenge_andRendersTheForm() {
        WebAuthnAuthenticator authenticator = authenticator((t, u, i) -> true);
        AuthenticationContext ctx = context();

        authenticator.authenticate(ctx);

        assertThat(ctx.status()).isEqualTo(AuthenticationContext.Status.CHALLENGE);
        assertThat(ctx.challengeView()).isEqualTo("webauthn-form");
        assertThat(ctx.getAttribute("webauthn.challenge")).isNotNull(); // a server challenge was stashed
    }

    @Test
    void action_packsTheAssertionWithChallengeAndVerifiesUnderWebauthnType() {
        AtomicReference<String> sentType = new AtomicReference<>();
        AtomicReference<String> sentInput = new AtomicReference<>();
        CredentialVerifier capturing = (type, userId, input) -> {
            sentType.set(type);
            sentInput.set(input);
            return true;
        };
        WebAuthnAuthenticator authenticator = authenticator(capturing);
        AuthenticationContext ctx = context();
        authenticator.authenticate(ctx); // issues + stashes the challenge
        ctx.submit(Map.of("credentialId", "cred-123", "authenticatorData", "ad",
                "clientDataJSON", "cdj", "signature", "sig"));

        authenticator.action(ctx);

        assertThat(ctx.status()).isEqualTo(AuthenticationContext.Status.SUCCESS);
        assertThat(sentType.get()).isEqualTo("webauthn");
        assertThat(sentInput.get()).contains("cred-123").contains("rpId").contains("challenge");
    }

    @Test
    void action_verificationFails_fails() {
        WebAuthnAuthenticator authenticator = authenticator((t, u, i) -> false);
        AuthenticationContext ctx = context();
        authenticator.authenticate(ctx);
        ctx.submit(Map.of("credentialId", "cred-123", "authenticatorData", "ad",
                "clientDataJSON", "cdj", "signature", "sig"));

        authenticator.action(ctx);

        assertThat(ctx.status()).isEqualTo(AuthenticationContext.Status.FAILURE);
    }
}
