package group.mfnr.authorization.service.key;

import group.mfnr.authorization.domain.realm.RealmConfig;
import group.mfnr.authorization.domain.realm.RealmKey;
import io.helixiam.common.security.RSAKeyReader;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.stereotype.Service;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

/**
 * Bridges the {@link RealmKey} store to concrete Java keys for token signing/verification
 * (Helix IAM E1.4).
 *
 * <p>The signing realm's ACTIVE key is served as a {@link KeyPair}. In a standalone deployment
 * (the default for this microservice) the signing realm self-generates and persists its own key
 * on first use, like every other realm. If a {@code /jks} keypair is mounted (filesystem or
 * classpath), it is imported instead so the key material — and the JWT {@code kid} derived from
 * it — is identical at cutover from a prior deployment (continuity). Rotation (see
 * {@link RealmKeyService#rotate}) then introduces new ACTIVE keys while ROTATED keys remain
 * available as verification keys for the overlap window.
 */
@Service
public class KeyMaterialService {

    private static final Logger LOG = LogManager.getLogger(KeyMaterialService.class);

    /** The realm whose keys sign tokens for the (single-issuer) authorization server. */
    public static final String SIGNING_REALM_ID = RealmConfig.ADMIN_REALM_ID;

    private static final String JKS_PRIVATE = "/jks/private-key.pkcs8";
    private static final String JKS_PUBLIC = "/jks/public-key.cert";

    private final RealmKeyService realmKeyService;

    public KeyMaterialService(final RealmKeyService realmKeyService) {
        this.realmKeyService = realmKeyService;
    }

    /**
     * The ACTIVE signing keypair for {@code realm} (Helix IAM multi-tenant, MT-3). The admin realm
     * seeds from the existing {@code /jks} keypair so its token {@code kid} is unchanged at cutover
     * (continuity); every other realm gets its OWN freshly generated key — distinct material, so
     * tokens minted under {@code /realms/{realm}} are signed by, and verify against, that realm's JWKS.
     */
    public KeyPair activeKeyPair(final String realm) {
        final String realmId = (realm == null || realm.isBlank()) ? SIGNING_REALM_ID : realm;
        final RealmKey active;
        if (SIGNING_REALM_ID.equals(realmId) && RSAKeyReader.exists(JKS_PUBLIC) && RSAKeyReader.exists(JKS_PRIVATE)) {
            // Cutover continuity (e.g. migrating an existing deployment): import the mounted /jks
            // keypair so the signing realm's key material — and the JWT kid derived from it — is
            // unchanged. The read is guarded by exists() so the arguments are only evaluated when
            // the material is actually present.
            active = realmKeyService.getOrImportActive(SIGNING_REALM_ID, "RSA",
                    Base64.getEncoder().encodeToString(RSAKeyReader.getPublicKey(JKS_PUBLIC).getEncoded()),
                    Base64.getEncoder().encodeToString(RSAKeyReader.getPrivateKey(JKS_PRIVATE).getEncoded()));
        } else {
            // Standalone (the default for this microservice): no /jks mount, so the signing realm
            // self-generates and persists its own key on first use — exactly like every other realm.
            active = realmKeyService.getOrCreateActive(realmId);
        }
        return new KeyPair(toPublicKey(active.getPublicKey()), toPrivateKey(active.getPrivateKey()));
    }

    /** Public keys of {@code realm}'s ROTATED keys — published in its JWKS so pre-rotation tokens still verify. */
    public List<RSAPublicKey> rotatedPublicKeys(final String realm) {
        final String realmId = (realm == null || realm.isBlank()) ? SIGNING_REALM_ID : realm;
        final List<RSAPublicKey> keys = new ArrayList<>();
        for (final RealmKey key : realmKeyService.verificationKeys(realmId)) {
            if (RealmKey.Status.ROTATED.name().equals(key.getStatus())) {
                keys.add(toPublicKey(key.getPublicKey()));
            }
        }
        return keys;
    }

    private RSAPublicKey toPublicKey(final String base64Spki) {
        try {
            return (RSAPublicKey) KeyFactory.getInstance("RSA")
                    .generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(base64Spki)));
        } catch (final Exception e) {
            throw new IllegalStateException("Invalid stored public key", e);
        }
    }

    private RSAPrivateKey toPrivateKey(final String base64Pkcs8) {
        try {
            return (RSAPrivateKey) KeyFactory.getInstance("RSA")
                    .generatePrivate(new PKCS8EncodedKeySpec(Base64.getDecoder().decode(base64Pkcs8)));
        } catch (final Exception e) {
            throw new IllegalStateException("Invalid stored private key", e);
        }
    }
}
