package io.helixiam.authorization.flow.authenticators;

import io.helixiam.authorization.flow.spi.AuthenticationContext;
import io.helixiam.authorization.flow.spi.FactorClass;
import org.junit.jupiter.api.Test;

import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Helix IAM E2.3: the password authenticator is the identity-establishing first factor — it
 * prompts for credentials, verifies them via an injected {@link PasswordVerifier}, and on
 * success records the resolved user on the context for the rest of the flow.
 */
class PasswordAuthenticatorTest {

    private AuthenticationContext context() {
        return new AuthenticationContext("e-pass", "master", null);
    }

    @Test
    void metadata_isAKnowledgeFactorWithIdPassword() {
        PasswordAuthenticator authenticator = new PasswordAuthenticator((u, p) -> Optional.empty());

        assertThat(authenticator.metadata().id()).isEqualTo("password");
        assertThat(authenticator.metadata().factorClass()).isEqualTo(FactorClass.KNOWLEDGE);
    }

    @Test
    void authenticate_promptsForCredentials() {
        PasswordAuthenticator authenticator = new PasswordAuthenticator((u, p) -> Optional.empty());
        AuthenticationContext ctx = context();

        authenticator.authenticate(ctx);

        assertThat(ctx.status()).isEqualTo(AuthenticationContext.Status.CHALLENGE);
        assertThat(ctx.challengeView()).isEqualTo("login-form");
    }

    @Test
    void action_validCredentials_succeedsAndEstablishesTheUser() {
        PasswordAuthenticator authenticator = new PasswordAuthenticator((username, password) ->
                username.equals("admin@e2e.local") && password.equals("kubedna")
                        ? Optional.of("user-1") : Optional.empty());
        AuthenticationContext ctx = context();
        ctx.submit(Map.of("username", "admin@e2e.local", "password", "kubedna"));

        authenticator.action(ctx);

        assertThat(ctx.status()).isEqualTo(AuthenticationContext.Status.SUCCESS);
        assertThat(ctx.userId()).isEqualTo("user-1");
    }

    @Test
    void action_invalidCredentials_failsAndLeavesUserUnset() {
        PasswordAuthenticator authenticator = new PasswordAuthenticator((u, p) -> Optional.empty());
        AuthenticationContext ctx = context();
        ctx.submit(Map.of("username", "admin@e2e.local", "password", "wrong"));

        authenticator.action(ctx);

        assertThat(ctx.status()).isEqualTo(AuthenticationContext.Status.FAILURE);
        assertThat(ctx.userId()).isNull();
    }

    @Test
    void action_missingCredentials_fails() {
        PasswordAuthenticator authenticator = new PasswordAuthenticator((u, p) -> Optional.of("user-1"));
        AuthenticationContext ctx = context();

        authenticator.action(ctx);

        assertThat(ctx.status()).isEqualTo(AuthenticationContext.Status.FAILURE);
    }
}
