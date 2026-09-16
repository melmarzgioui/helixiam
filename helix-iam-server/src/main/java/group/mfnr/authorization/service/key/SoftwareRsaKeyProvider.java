package group.mfnr.authorization.service.key;

import org.springframework.stereotype.Component;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.UUID;

/**
 * Default {@link SigningKeyProvider}: generates RSA-2048 keys in the JVM (Helix IAM E1.4).
 *
 * <p>The private key is returned Base64-encoded and is encrypted at rest by the key store.
 * For hardware-backed keys, replace this with a PKCS#11/KMS provider implementing the same
 * interface — the key service is unaffected.
 */
@Component
public class SoftwareRsaKeyProvider implements SigningKeyProvider {

    private static final String ALGORITHM = "RSA";
    private static final int KEY_SIZE = 2048;

    @Override
    public String type() {
        return "software";
    }

    @Override
    public GeneratedKey generate() {
        try {
            final KeyPairGenerator generator = KeyPairGenerator.getInstance(ALGORITHM);
            generator.initialize(KEY_SIZE);
            final KeyPair keyPair = generator.generateKeyPair();
            final String publicKeyBase64 = Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded());
            final String privateKeyBase64 = Base64.getEncoder().encodeToString(keyPair.getPrivate().getEncoded());
            return new GeneratedKey(UUID.randomUUID().toString(), ALGORITHM, publicKeyBase64, privateKeyBase64);
        } catch (final NoSuchAlgorithmException e) {
            throw new IllegalStateException("RSA key generation unavailable", e);
        }
    }
}
