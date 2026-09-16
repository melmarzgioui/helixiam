package group.mfnr.authorization.flow.authenticators;

import group.mfnr.authorization.flow.spi.AuthenticationContext;
import group.mfnr.authorization.flow.spi.AuthenticatorCategory;
import group.mfnr.authorization.flow.spi.ConfigProperty;
import group.mfnr.authorization.flow.spi.FactorClass;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Helix IAM (federation): the "Identity Provider Redirector" flow step. The redirect-out itself happens
 * before the password screen (in {@code LoginController}); by the time the engine runs this step it is
 * the post-broker replay (identity already established) so it resolves to success and never loops.
 */
class IdentityProviderRedirectAuthenticatorTest {

    private final IdentityProviderRedirectAuthenticator authenticator = new IdentityProviderRedirectAuthenticator();

    @Test
    void metadata_declaresIdFactorAndConfigSchema() {
        assertThat(authenticator.metadata().id()).isEqualTo("idp-redirect");
        assertThat(authenticator.metadata().factorClass()).isEqualTo(FactorClass.NONE);
        assertThat(authenticator.metadata().levelOfAssurance()).isZero();
        // A method (a sign-in step the user performs) — NOT a flow condition, so the console shows it
        // under "Add a method" despite its NONE/LoA-0 factor.
        assertThat(authenticator.metadata().category()).isEqualTo(AuthenticatorCategory.METHOD);
        assertThat(authenticator.metadata().configSchema())
                .extracting(ConfigProperty::key)
                .containsExactly("providerAlias", "mode");
    }

    @Test
    void authenticate_whenIdentityAlreadyEstablished_succeeds() {
        final AuthenticationContext ctx = new AuthenticationContext("e1", "master", "user-1",
                Map.of("providerAlias", "digid", "mode", "REDIRECT"));

        authenticator.authenticate(ctx);

        assertThat(ctx.status()).isEqualTo(AuthenticationContext.Status.SUCCESS);
    }

    @Test
    void authenticate_withNoIdentity_challengesRatherThanLooping() {
        final AuthenticationContext ctx = new AuthenticationContext("e1", "master", null,
                Map.of("providerAlias", "digid", "mode", "REDIRECT"));

        authenticator.authenticate(ctx);

        assertThat(ctx.status()).isEqualTo(AuthenticationContext.Status.CHALLENGE);
    }

    @Test
    void context_exposesPerExecutionConfig() {
        final AuthenticationContext ctx = new AuthenticationContext("e1", "master", "user-1",
                Map.of("providerAlias", "digid"));

        assertThat(ctx.config("providerAlias")).isEqualTo("digid");
        assertThat(ctx.config("mode")).isNull();
    }
}
