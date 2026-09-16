package group.mfnr.authorization.flow.spi;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Helix IAM E2.3: the registry resolves the authenticator a flow execution names by id, and is
 * the catalogue the admin console reads to list installed authenticators.
 */
class AuthenticatorRegistryTest {

    /** Minimal stand-in authenticator with a given id (no real auth behaviour). */
    private static Authenticator stub(final String id) {
        return new Authenticator() {
            @Override
            public AuthenticatorMetadata metadata() {
                return AuthenticatorMetadata.of(id, id, FactorClass.KNOWLEDGE, 1);
            }

            @Override
            public void authenticate(final AuthenticationContext context) {
                context.success();
            }
        };
    }

    @Test
    void resolvesAnAuthenticatorByItsMetadataId() {
        Authenticator password = stub("password");
        AuthenticatorRegistry registry = new AuthenticatorRegistry(List.of(password, stub("otp")));

        assertThat(registry.get("password")).isSameAs(password);
    }

    @Test
    void unknownId_throws() {
        AuthenticatorRegistry registry = new AuthenticatorRegistry(List.of(stub("password")));

        assertThatThrownBy(() -> registry.get("nope"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("nope");
    }

    @Test
    void listsEveryRegisteredAuthenticator() {
        AuthenticatorRegistry registry = new AuthenticatorRegistry(List.of(stub("password"), stub("otp")));

        assertThat(registry.all()).extracting(a -> a.metadata().id())
                .containsExactlyInAnyOrder("password", "otp");
    }

    @Test
    void duplicateId_isRejectedAtConstruction() {
        assertThatThrownBy(() -> new AuthenticatorRegistry(List.of(stub("password"), stub("password"))))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("password");
    }
}
