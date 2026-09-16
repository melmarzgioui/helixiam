package io.helixiam.authorization.flow.authenticators;

import io.helixiam.authorization.flow.spi.AuthenticationContext;
import io.helixiam.authorization.flow.spi.Authenticator;
import io.helixiam.authorization.flow.spi.AuthenticatorMetadata;
import io.helixiam.authorization.flow.spi.ConfigProperty;
import io.helixiam.authorization.flow.spi.FactorClass;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * Helix IAM (federation): the "Identity Provider Redirector" flow step. It lets an Application (via
 * its bound login flow) start authentication at an external IdP (e.g. {@code digid}); the user
 * authenticates there and returns through the existing federation broker, which maps the IdP
 * attributes to a local identity (link / JIT) and re-runs this flow.
 *
 * <p>This authenticator carries the admin config ({@code providerAlias} + {@code mode}) but does no
 * redirect of its own — the redirect-out happens <em>before</em> the password screen, in
 * {@code LoginController}, which reads this step's config from the in-flight flow. By the time the
 * engine actually runs this step it is always the <strong>post-broker replay</strong>
 * ({@code FederatedLoginCompleter} sets the resolved user before {@code begin}), or a local login the
 * user chose in OPTION mode — in both cases an identity is already established, so the step resolves
 * to {@link AuthenticationContext#success() success} and composes with any later factors without
 * looping. The {@link AuthenticationContext#challenge challenge} branch is a defensive fallback for
 * the (unreached) case where the step runs with no established identity.
 */
@Component
public class IdentityProviderRedirectAuthenticator implements Authenticator {

    /** SPI id referenced by flow executions and the console editor. */
    public static final String ID = "idp-redirect";
    /** Config key: the single external identity-provider alias to redirect to (REDIRECT mode). */
    public static final String PROVIDER_ALIAS = "providerAlias";
    /** Config key: comma-separated identity-provider aliases to offer beside local login (OPTION mode). */
    public static final String PROVIDER_ALIASES = "providerAliases";
    /** Config key: how the app federates — REDIRECT, OPTION (local + providers), or LOCAL_ONLY. */
    public static final String MODE = "mode";
    /** Auto-redirect to one provider, skipping the local username/password screen. */
    public static final String MODE_REDIRECT = "REDIRECT";
    /** Show the local login form plus one or more identity-provider buttons as alternatives. */
    public static final String MODE_OPTION = "OPTION";
    /** Show only the local login form — suppress every identity-provider button for this app. */
    public static final String MODE_LOCAL_ONLY = "LOCAL_ONLY";

    /** Defensive challenge view — not reached in practice (see class doc). */
    static final String VIEW = "login";

    @Override
    public AuthenticatorMetadata metadata() {
        return new AuthenticatorMetadata(ID, "Identity Provider Redirector", FactorClass.NONE, 0,
                List.of(
                        ConfigProperty.string(PROVIDER_ALIAS, "Identity provider", true),
                        ConfigProperty.select(MODE, "Mode", List.of(MODE_REDIRECT, MODE_OPTION))));
    }

    @Override
    public void authenticate(final AuthenticationContext context) {
        // Post-broker replay (or a local login in OPTION mode): the identity is already established.
        if (context.userId() != null) {
            context.success();
            return;
        }
        // Not reached in the standard flows (LoginController handles the redirect-out before password);
        // fail-safe rather than loop, so a misconfigured direct run does not hang.
        context.challenge(VIEW);
    }
}
