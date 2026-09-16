package io.helixiam.authorization.idp.saml;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.opensaml.core.config.InitializationService;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.Unmarshaller;
import org.opensaml.saml.saml2.core.LogoutResponse;
import org.opensaml.saml.saml2.core.StatusCode;
import org.opensaml.saml.security.impl.SAMLSignatureProfileValidator;
import org.opensaml.security.x509.BasicX509Credential;
import org.opensaml.xmlsec.signature.support.SignatureValidator;
import org.w3c.dom.Element;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Date;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Helix IAM E7.2: the SAML Single Logout response is genuinely signed by the IdP key, carries
 * Status=Success and echoes the SP's LogoutRequest id. Verified offline against the IdP cert.
 */
class SamlLogoutResponseIssuerTest {

    private static final String IDP_ENTITY = "https://helix.test/idp";
    private static X509Certificate idpCert;
    private static String idpCertPem;
    private static String idpKeyPem;

    private final SamlLogoutResponseIssuer issuer = new SamlLogoutResponseIssuer();

    @BeforeAll
    static void init() throws Exception {
        InitializationService.initialize();
        final KeyPair idpKey = rsa();
        idpCert = selfSigned(idpKey, "CN=HelixIdP");
        idpCertPem = pem(idpCert);
        idpKeyPem = pkcs8Pem(idpKey.getPrivate());
    }

    @Test
    void issuesASignedSuccessLogoutResponse() throws Exception {
        final String encoded = issuer.issueLogoutResponse(
                new SamlIdpConfig(IDP_ENTITY, idpCertPem, idpKeyPem), "https://rp.example/slo", "_logout-req-1");

        final LogoutResponse response = parse(encoded);
        assertThat(response.getIssuer().getValue()).isEqualTo(IDP_ENTITY);
        assertThat(response.getInResponseTo()).isEqualTo("_logout-req-1");
        assertThat(response.getStatus().getStatusCode().getValue()).isEqualTo(StatusCode.SUCCESS);

        assertThat(response.getSignature()).isNotNull();
        new SAMLSignatureProfileValidator().validate(response.getSignature());
        SignatureValidator.validate(response.getSignature(), new BasicX509Credential(idpCert)); // throws if invalid
    }

    private static LogoutResponse parse(final String encoded) throws Exception {
        final byte[] xml = Base64.getDecoder().decode(encoded);
        final Element element = XMLObjectProviderRegistrySupport.getParserPool()
                .parse(new ByteArrayInputStream(xml)).getDocumentElement();
        final Unmarshaller unmarshaller = XMLObjectProviderRegistrySupport.getUnmarshallerFactory().getUnmarshaller(element);
        return (LogoutResponse) unmarshaller.unmarshall(element);
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
