package group.mfnr.authorization.service.device;

import org.springframework.stereotype.Component;

import java.security.KeyFactory;
import java.security.spec.X509EncodedKeySpec;

/**
 * Helix IAM E4.1: the "none" attestation verifier — trust-on-first-use, the dev default when
 * platform attestation isn't enforced. It does not check platform roots, but still requires a bound
 * server nonce (anti-replay) and a parseable P-256 device key (so enrollment can't store junk).
 * Apple App Attest / Android Key Attestation verifiers ship later as additional beans.
 */
@Component
public class SelfAttestationVerifier implements AttestationVerifier {

    @Override
    public String platform() {
        return "none";
    }

    @Override
    public boolean verify(final byte[] attestation, final byte[] nonce, final byte[] publicKey) {
        if (nonce == null || nonce.length == 0 || publicKey == null) {
            return false;
        }
        try {
            KeyFactory.getInstance("EC").generatePublic(new X509EncodedKeySpec(publicKey));
            return true;
        } catch (final Exception e) {
            return false;
        }
    }
}
