package group.mfnr.authorization.idp.saml;

import group.mfnr.authorization.amqp.ServiceProviderPublisher;
import group.mfnr.authorization.security.realm.RealmContextHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.springframework.stereotype.Component;

import javax.security.auth.x500.X500Principal;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Helix IAM — per-realm SAML2 IdP signing material.
 *
 * <p>Each realm is its own SAML Identity Provider, so it must sign assertions with its <b>own</b>
 * certificate — never a single deployment-wide key. This source derives that certificate from the
 * realm's <b>active signing key</b> (the very key the OIDC {@code RealmJwkSource}/JWKS publishes,
 * fetched over AMQP via {@link ServiceProviderPublisher#retrieveKeyPair(String)}), by wrapping the
 * public key in a deterministic self-signed X.509 certificate. Consequences:
 *
 * <ul>
 *   <li>SAML and OIDC share one keypair per realm, so rotating the realm key (Realm Keys UI /
 *       {@code /admin/realms/{realm}/keys/rotate}) rotates the SAML signing cert too.</li>
 *   <li>The cert is <b>deterministic</b> for a stable key (fixed serial + validity + RSA PKCS#1
 *       signature), so metadata is byte-stable and SP-pinned fingerprints don't drift on restart.</li>
 *   <li>Cached per realm on a short TTL; a rotation propagates within the window without a restart,
 *       mirroring {@link group.mfnr.authorization.security.RealmJwkSource}.</li>
 * </ul>
 *
 * <p>The IdP {@code entityId} stays the configured {@code helix.idp.saml.entity-id} (a per-realm
 * entityId is a separate change that would require re-registering SPs), so only the signing material
 * becomes per-realm here.
 */
@Component
public class RealmSamlCredentialSource {

    private static final String DEFAULT_REALM = "master";
    private static final long REFRESH_TTL_MS = 30_000L;

    // Fixed validity window → deterministic certificate bytes for a stable key.
    private static final Date NOT_BEFORE = Date.from(Instant.parse("2000-01-01T00:00:00Z"));
    private static final Date NOT_AFTER = Date.from(Instant.parse("2099-12-31T23:59:59Z"));

    private final ServiceProviderPublisher serviceProviderPublisher;
    private final SamlIdpProperties properties;
    private final long ttlMs;

    private final ConcurrentHashMap<String, Cached> byRealm = new ConcurrentHashMap<>();

    private record Cached(String kid, SamlIdpConfig config, long fetchedAtMs) {
    }

    @org.springframework.beans.factory.annotation.Autowired
    public RealmSamlCredentialSource(final ServiceProviderPublisher serviceProviderPublisher,
                                     final SamlIdpProperties properties) {
        this(serviceProviderPublisher, properties, REFRESH_TTL_MS);
    }

    /** TTL-overridable constructor for tests (rotation propagation). */
    RealmSamlCredentialSource(final ServiceProviderPublisher serviceProviderPublisher,
                              final SamlIdpProperties properties, final long ttlMs) {
        this.serviceProviderPublisher = serviceProviderPublisher;
        this.properties = properties;
        this.ttlMs = ttlMs;
    }

    /** The SAML IdP signing config for the CURRENT realm (from {@link RealmContextHolder}). */
    public SamlIdpConfig current() {
        return forRealm(RealmContextHolder.get() == null ? DEFAULT_REALM : RealmContextHolder.get());
    }

    /** The SAML IdP signing config (entityId + cert PEM + private-key PEM) for the given realm. */
    public SamlIdpConfig forRealm(final String realmOrNull) {
        final String realm = realmOrNull == null || realmOrNull.isBlank() ? DEFAULT_REALM : realmOrNull;
        final long now = System.currentTimeMillis();
        final Cached existing = byRealm.get(realm);
        if (existing != null && now - existing.fetchedAtMs() <= ttlMs) {
            return existing.config();
        }
        final KeyPair keyPair = serviceProviderPublisher.retrieveKeyPair(realm);
        if (keyPair == null) {
            if (existing != null) {
                return existing.config(); // serve the last good cert if the store hiccups
            }
            throw new IllegalStateException("No active signing key for realm '" + realm + "' — cannot sign SAML");
        }
        final String kid = kid(keyPair.getPublic());
        // Key unchanged since last build → reuse the (deterministic) cert, just refresh the timestamp.
        if (existing != null && existing.kid().equals(kid)) {
            byRealm.put(realm, new Cached(kid, existing.config(), now));
            return existing.config();
        }
        final SamlIdpConfig config = build(realm, keyPair);
        byRealm.put(realm, new Cached(kid, config, now));
        return config;
    }

    private SamlIdpConfig build(final String realm, final KeyPair keyPair) {
        try {
            final X509Certificate cert = selfSigned(realm, keyPair);
            final String certPem = pem("CERTIFICATE", cert.getEncoded());
            final String keyPem = pem("PRIVATE KEY", keyPair.getPrivate().getEncoded());
            return new SamlIdpConfig(properties.getEntityId(), certPem, keyPem);
        } catch (final Exception e) {
            throw new IllegalStateException("Failed to build SAML signing certificate for realm '" + realm + "'", e);
        }
    }

    /** A deterministic self-signed X.509 cert wrapping the realm's public key, signed by its private key. */
    private static X509Certificate selfSigned(final String realm, final KeyPair keyPair) throws Exception {
        final PublicKey publicKey = keyPair.getPublic();
        final PrivateKey privateKey = keyPair.getPrivate();
        final X500Principal dn = new X500Principal("CN=helix-idp-" + realm);
        // Deterministic positive serial from the public key so the cert bytes are stable for a stable key.
        final byte[] modulusHash = MessageDigest.getInstance("SHA-256").digest(publicKey.getEncoded());
        final BigInteger serial = new BigInteger(1, modulusHash);
        final JcaX509v3CertificateBuilder builder =
                new JcaX509v3CertificateBuilder(dn, serial, NOT_BEFORE, NOT_AFTER, dn, publicKey);
        final ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(privateKey);
        return new JcaX509CertificateConverter().getCertificate(builder.build(signer));
    }

    private static String kid(final PublicKey publicKey) {
        try {
            return Base64.getEncoder().encodeToString(
                    MessageDigest.getInstance("SHA-256").digest(publicKey.getEncoded()));
        } catch (final Exception e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    private static String pem(final String type, final byte[] der) {
        return "-----BEGIN " + type + "-----\n"
                + Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(der)
                + "\n-----END " + type + "-----\n";
    }
}
