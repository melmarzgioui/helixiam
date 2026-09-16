package group.mfnr.authorization.service.device;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Helix IAM E4.1: the device factor's signing crypto is ES256 (ECDSA P-256 + SHA-256) over DER
 * signatures, with the device public key supplied as SPKI (X.509 SubjectPublicKeyInfo) — the exact
 * shape an Apple Secure Enclave / Android StrongBox key exports. Verifying against generated P-256
 * keys is the one part of the device factor we can fully prove without a real device.
 */
class DeviceSignatureVerifierTest {

    private static KeyPair p256() throws Exception {
        final KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(new ECGenParameterSpec("secp256r1"));
        return kpg.generateKeyPair();
    }

    private static byte[] signDer(final KeyPair kp, final byte[] message) throws Exception {
        final Signature s = Signature.getInstance("SHA256withECDSA");
        s.initSign(kp.getPrivate());
        s.update(message);
        return s.sign();
    }

    @Test
    void verifiesAGenuineEs256SignatureOverTheChallenge() throws Exception {
        final KeyPair kp = p256();
        final byte[] challenge = "helix-device-challenge".getBytes(StandardCharsets.UTF_8);
        final byte[] sig = signDer(kp, challenge);

        assertThat(DeviceSignatureVerifier.verify(kp.getPublic().getEncoded(), challenge, sig)).isTrue();
    }

    @Test
    void rejectsASignatureOverDifferentBytes() throws Exception {
        final KeyPair kp = p256();
        final byte[] sig = signDer(kp, "amount=10".getBytes(StandardCharsets.UTF_8));

        assertThat(DeviceSignatureVerifier.verify(kp.getPublic().getEncoded(),
                "amount=9999".getBytes(StandardCharsets.UTF_8), sig)).isFalse();
    }

    @Test
    void rejectsASignatureFromADifferentKey() throws Exception {
        final byte[] challenge = "helix".getBytes(StandardCharsets.UTF_8);
        final byte[] sig = signDer(p256(), challenge);

        assertThat(DeviceSignatureVerifier.verify(p256().getPublic().getEncoded(), challenge, sig)).isFalse();
    }

    @Test
    void rejectsMalformedPublicKeyOrSignatureWithoutThrowing() {
        assertThat(DeviceSignatureVerifier.verify(new byte[]{1, 2, 3}, new byte[]{4}, new byte[]{5})).isFalse();
    }
}
