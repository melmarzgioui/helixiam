package group.mfnr.authorization.idp.saml;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.opensaml.core.config.InitializationService;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Date;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Helix IAM SSO P8: parses an inbound SP {@code <LogoutRequest>} into the SP entity id, request id and
 * NameID, and validates its XML signature against the SP's registered certificate (a mismatching key is
 * rejected — the security gate for IdP SLO).
 */
class SamlLogoutRequestParserTest {

    private static final String SP_ENTITY = "https://sp.example/metadata";
    private static X509Certificate spCert;
    private static String spCertPem;
    private static String spKeyPem;
    private static X509Certificate otherCertPem;
    private static String otherPem;

    private final SamlLogoutRequestParser parser = new SamlLogoutRequestParser();
    private final SamlLogoutRequestIssuer issuer = new SamlLogoutRequestIssuer();

    @BeforeAll
    static void init() throws Exception {
        InitializationService.initialize();
        final KeyPair spKey = rsa();
        spCert = selfSigned(spKey, "CN=SP");
        spCertPem = pem(spCert);
        spKeyPem = pkcs8Pem(spKey.getPrivate());
        final KeyPair other = rsa();
        otherCertPem = selfSigned(other, "CN=Other");
        otherPem = pem(otherCertPem);
    }

    /** A LogoutRequest the SP would send — signed with the SP key, issued by the SP, naming the user. */
    private String spLogoutRequest(final String nameId) {
        return issuer.issueLogoutRequest(new SamlIdpConfig(SP_ENTITY, spCertPem, spKeyPem),
                "https://helix.test/realms/master/saml/idp/slo", nameId);
    }

    @Test
    void parse_extractsEntityIdRequestIdAndNameId() {
        final SamlLogoutRequestParser.LogoutRequestInfo info = parser.parse(spLogoutRequest("alice@example.test"), false);
        assertThat(info.spEntityId()).isEqualTo(SP_ENTITY);
        assertThat(info.requestId()).isNotBlank();
        assertThat(info.nameId()).isEqualTo("alice@example.test");
    }

    @Test
    void signatureValid_trueForTheRegisteredCert() {
        assertThat(parser.isSignatureValid(spLogoutRequest("alice@example.test"), false, spCertPem)).isTrue();
    }

    @Test
    void signatureValid_falseForAMismatchingCert() {
        assertThat(parser.isSignatureValid(spLogoutRequest("alice@example.test"), false, otherPem)).isFalse();
    }

    @Test
    void signatureValid_falseWhenNoCertConfigured() {
        assertThat(parser.isSignatureValid(spLogoutRequest("alice@example.test"), false, null)).isFalse();
    }

    private static KeyPair rsa() throws Exception {
        final KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        return kpg.generateKeyPair();
    }

    private static X509Certificate selfSigned(final KeyPair kp, final String dn) throws Exception {
        final long now = System.currentTimeMillis();
        final org.bouncycastle.asn1.x500.X500Name name = new org.bouncycastle.asn1.x500.X500Name(dn);
        final JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                name, BigInteger.valueOf(now), new Date(now - 60_000), new Date(now + 86_400_000L), name, kp.getPublic());
        final ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(kp.getPrivate());
        final X509CertificateHolder holder = builder.build(signer);
        return new JcaX509CertificateConverter().getCertificate(holder);
    }

    private static String pem(final X509Certificate cert) throws Exception {
        return "-----BEGIN CERTIFICATE-----\n"
                + Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(cert.getEncoded())
                + "\n-----END CERTIFICATE-----\n";
    }

    private static String pkcs8Pem(final PrivateKey key) {
        return "-----BEGIN PRIVATE KEY-----\n"
                + Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(key.getEncoded())
                + "\n-----END PRIVATE KEY-----\n";
    }
}
