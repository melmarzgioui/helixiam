package io.helixiam.authorization.flow.authenticators;

import io.helixiam.authorization.flow.spi.AuthenticationContext;
import io.helixiam.authorization.flow.spi.Authenticator;
import io.helixiam.authorization.flow.spi.AuthenticatorMetadata;
import io.helixiam.authorization.flow.spi.FactorClass;
import org.springframework.stereotype.Component;

/**
 * Reference Helix authenticator plugin: requires the user to accept terms before continuing.
 *
 * <p>This is the canonical example of the pluggable SPI: it is just a class that implements
 * {@link Authenticator} and is a Spring {@code @Component}. That is all that is needed — Helix
 * discovers it at startup (see {@code FlowConfig.authenticatorRegistry}), registers it under
 * {@code metadata().id() == "consent"}, and any realm flow may then reference and execute it.
 * No change to the engine, registry, or config is required to add a factor this way.
 */
@Component
public class ConsentAuthenticator implements Authenticator {

    static final String VIEW = "consent-form";
    static final String ACCEPT_PARAM = "accept";

    @Override
    public AuthenticatorMetadata metadata() {
        return AuthenticatorMetadata.of("consent", "Accept Terms", FactorClass.NONE, 0);
    }

    @Override
    public void authenticate(final AuthenticationContext context) {
        context.challenge(VIEW);
    }

    @Override
    public void action(final AuthenticationContext context) {
        if ("true".equals(context.formParameter(ACCEPT_PARAM))) {
            context.success();
        } else {
            context.failure("Terms not accepted");
        }
    }
}
