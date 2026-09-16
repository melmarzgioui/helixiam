package io.helixiam.authorization.service.credential;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** Helix IAM: the credential-provider registry resolves a provider by its type id. */
class CredentialProviderRegistryTest {

    private static CredentialProvider stub(final String type, final boolean result) {
        return new CredentialProvider() {
            @Override public String type() { return type; }
            @Override public boolean verify(final String userId, final String input) { return result; }
        };
    }

    @Test
    void resolvesAProviderByType_andVerifiesThroughIt() {
        CredentialProviderRegistry registry =
                new CredentialProviderRegistry(List.of(stub("hotp", true), stub("recovery-code", false)));

        assertThat(registry.verify("hotp", "user-1", "123456")).isTrue();
        assertThat(registry.verify("recovery-code", "user-1", "ABCD")).isFalse();
    }

    @Test
    void unknownType_throws() {
        CredentialProviderRegistry registry = new CredentialProviderRegistry(List.of(stub("hotp", true)));

        assertThatThrownBy(() -> registry.verify("nope", "user-1", "x"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("nope");
    }

    @Test
    void duplicateType_isRejected() {
        assertThatThrownBy(() -> new CredentialProviderRegistry(List.of(stub("hotp", true), stub("hotp", false))))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("hotp");
    }
}
