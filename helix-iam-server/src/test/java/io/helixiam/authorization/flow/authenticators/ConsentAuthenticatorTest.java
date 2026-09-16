package io.helixiam.authorization.flow.authenticators;

import io.helixiam.authorization.flow.spi.AuthenticationContext;
import io.helixiam.authorization.flow.spi.FactorClass;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Helix IAM: reference plugin authenticator (terms/consent). Demonstrates how a third party adds
 * a factor — implement {@code Authenticator}, mark it a Spring {@code @Component}, and Helix
 * auto-discovers and registers it. Also a genuinely useful step (force consent before login).
 */
class ConsentAuthenticatorTest {

    private final ConsentAuthenticator authenticator = new ConsentAuthenticator();

    private AuthenticationContext context() {
        return new AuthenticationContext("e-consent", "master", "user-1");
    }

    @Test
    void metadata_hasAStableIdAndNoFactorOfItsOwn() {
        assertThat(authenticator.metadata().id()).isEqualTo("consent");
        assertThat(authenticator.metadata().factorClass()).isEqualTo(FactorClass.NONE);
    }

    @Test
    void authenticate_showsTheConsentScreen() {
        AuthenticationContext ctx = context();

        authenticator.authenticate(ctx);

        assertThat(ctx.status()).isEqualTo(AuthenticationContext.Status.CHALLENGE);
        assertThat(ctx.challengeView()).isEqualTo("consent-form");
    }

    @Test
    void action_whenAccepted_succeeds() {
        AuthenticationContext ctx = context();
        ctx.submit(Map.of("accept", "true"));

        authenticator.action(ctx);

        assertThat(ctx.status()).isEqualTo(AuthenticationContext.Status.SUCCESS);
    }

    @Test
    void action_whenNotAccepted_fails() {
        AuthenticationContext ctx = context();

        authenticator.action(ctx);

        assertThat(ctx.status()).isEqualTo(AuthenticationContext.Status.FAILURE);
    }
}
