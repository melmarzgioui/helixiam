package io.helixiam.authorization.service.device;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Helix IAM E4.1: the attestation registry auto-discovers {@link AttestationVerifier} beans and
 * routes enrollment to the right one by platform — the same drop-in SPI shape as the credential and
 * authenticator registries. Duplicate platforms are rejected at startup.
 */
class AttestationVerifierRegistryTest {

    private static AttestationVerifier stub(final String platform, final boolean result) {
        return new AttestationVerifier() {
            @Override public String platform() { return platform; }
            @Override public boolean verify(final byte[] a, final byte[] n, final byte[] k) { return result; }
        };
    }

    @Test
    void routesToTheVerifierForThePlatform() {
        final AttestationVerifierRegistry registry =
                new AttestationVerifierRegistry(List.of(stub("none", true), stub("apple-app-attest", false)));

        assertThat(registry.verify("none", new byte[0], new byte[]{1}, new byte[]{2})).isTrue();
        assertThat(registry.verify("apple-app-attest", new byte[0], new byte[]{1}, new byte[]{2})).isFalse();
    }

    @Test
    void rejectsAnUnknownPlatform() {
        final AttestationVerifierRegistry registry = new AttestationVerifierRegistry(List.of(stub("none", true)));

        assertThatThrownBy(() -> registry.verify("ghost", new byte[0], new byte[]{1}, new byte[]{2}))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void rejectsDuplicatePlatformsAtStartup() {
        assertThatThrownBy(() -> new AttestationVerifierRegistry(List.of(stub("none", true), stub("none", false))))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
