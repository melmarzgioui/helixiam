package group.mfnr.authorization.service.device;

import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;

/**
 * Helix IAM E4.1: verifies an ES256 (ECDSA P-256 + SHA-256) signature produced by a device's
 * Secure-Enclave/StrongBox key over exact challenge bytes (WYSIWYS / dynamic linking). The public
 * key is supplied as SPKI (X.509 {@code SubjectPublicKeyInfo}) and the signature in DER form — the
 * shapes mobile platforms export. Any malformed input verifies as {@code false} rather than throws.
 */
public final class DeviceSignatureVerifier {

    private DeviceSignatureVerifier() {
    }

    /**
     * @param spki         the device public key as X.509 SubjectPublicKeyInfo (EC P-256)
     * @param message      the exact bytes the device signed (the server challenge / canonical txn)
     * @param derSignature the ECDSA signature in DER encoding
     * @return true iff {@code derSignature} is a valid ES256 signature of {@code message} by the key
     */
    public static boolean verify(final byte[] spki, final byte[] message, final byte[] derSignature) {
        try {
            final PublicKey key = KeyFactory.getInstance("EC").generatePublic(new X509EncodedKeySpec(spki));
            final Signature verifier = Signature.getInstance("SHA256withECDSA");
            verifier.initVerify(key);
            verifier.update(message);
            return verifier.verify(derSignature);
        } catch (final Exception e) {
            return false;
        }
    }
}
