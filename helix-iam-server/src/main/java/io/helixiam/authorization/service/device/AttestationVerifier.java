package io.helixiam.authorization.service.device;

/**
 * Helix IAM E4.1: pluggable platform-attestation verifier for device enrollment. Each verifier
 * proves a freshly generated device key really lives in genuine platform hardware (Apple App
 * Attest / Android Key Attestation) by checking the attestation statement against the platform
 * roots over a server nonce. Auto-discovered like the other Helix SPIs: drop a {@code @Component}
 * and {@link AttestationVerifierRegistry} routes to it by {@link #platform()}.
 */
public interface AttestationVerifier {

    /** Platform id this verifier handles, e.g. "apple-app-attest", "android-key", or "none". */
    String platform();

    /**
     * @param attestation the platform attestation statement (empty for the "none" verifier)
     * @param nonce       the server-issued enrollment nonce the attestation must be bound to
     * @param publicKey   the device public key as X.509 SubjectPublicKeyInfo (EC P-256)
     * @return true iff the attestation is valid for this platform and binds the given key + nonce
     */
    boolean verify(byte[] attestation, byte[] nonce, byte[] publicKey);
}
