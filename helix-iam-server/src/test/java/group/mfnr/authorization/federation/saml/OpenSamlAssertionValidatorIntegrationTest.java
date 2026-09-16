package group.mfnr.authorization.federation.saml;

import net.shibboleth.utilities.java.support.xml.SerializeSupport;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.opensaml.core.config.InitializationService;
import org.opensaml.core.xml.XMLObjectBuilderFactory;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.schema.XSString;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.Attribute;
import org.opensaml.saml.saml2.core.AttributeStatement;
import org.opensaml.saml.saml2.core.AttributeValue;
import org.opensaml.saml.saml2.core.Audience;
import org.opensaml.saml.saml2.core.AudienceRestriction;
import org.opensaml.saml.saml2.core.Conditions;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.core.NameID;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.core.Subject;
import org.opensaml.security.x509.BasicX509Credential;
import org.opensaml.xmlsec.signature.Signature;
import org.opensaml.xmlsec.signature.support.SignatureConstants;
import org.opensaml.xmlsec.signature.support.Signer;

import javax.xml.namespace.QName;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Date;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Helix IAM E5.2: live validation of {@link OpenSamlAssertionValidator}. Mints a genuinely XML-signed
 * SAML Response with OpenSAML (signed by a BouncyCastle self-signed cert), then proves the validator
 * accepts it and rejects a response signed by an unknown cert or carrying the wrong audience. Fully
 * offline — no external IdP.
 */
class OpenSamlAssertionValidatorIntegrationTest {

    private static final String IDP_ENTITY = "https://idp.corp/entity";
    private static final String SP_ENTITY = "https://helix.test/sp";

    private static KeyPair idpKey;
    private static X509Certificate idpCert;
    private static X509Certificate foreignCert;
    private static String idpCertPem;

    private final OpenSamlAssertionValidator validator =
            new OpenSamlAssertionValidator(new InMemorySamlAssertionReplayCache());

    @BeforeAll
    static void init() throws Exception {
        InitializationService.initialize();
        idpKey = rsa();
        idpCert = selfSigned(idpKey, "CN=IdP");
        idpCertPem = pem(idpCert);
        foreignCert = selfSigned(rsa(), "CN=Evil"); // a cert NOT trusted by the SP config
    }

    @Test
    void acceptsAGenuineSignedResponse() throws Exception {
        final String response = signedResponse(idpKey, idpCert, IDP_ENTITY, SP_ENTITY, "ada@corp");
        final SamlProviderConfig config = config(idpCertPem, SP_ENTITY);

        final SamlAssertionValidator.ValidatedAssertion assertion = validator.validate(config, response, "relay");

        assertThat(assertion.nameId()).isEqualTo("ada@corp");
        assertThat(assertion.attributes()).containsEntry("mail", "ada@corp");
    }

    @Test
    void rejectsAResponseSignedByAnUnknownCertificate() throws Exception {
        final KeyPair foreignKey = rsa();
        final X509Certificate notTheConfiguredCert = selfSigned(foreignKey, "CN=Evil");
        final String response = signedResponse(foreignKey, notTheConfiguredCert, IDP_ENTITY, SP_ENTITY, "ada@corp");
        final SamlProviderConfig config = config(idpCertPem, SP_ENTITY); // expects the genuine IdP cert

        assertThatThrownBy(() -> validator.validate(config, response, "relay"))
                .isInstanceOf(IllegalStateException.class);
    }

    @Test
    void rejectsAResponseForTheWrongAudience() throws Exception {
        final String response = signedResponse(idpKey, idpCert, IDP_ENTITY, "https://someone-else/sp", "ada@corp");
        final SamlProviderConfig config = config(idpCertPem, SP_ENTITY);

        assertThatThrownBy(() -> validator.validate(config, response, "relay"))
                .isInstanceOf(IllegalStateException.class);
    }

    @Test
    void rejectsAReplayedAssertion() throws Exception {
        final String response = signedResponse(idpKey, idpCert, IDP_ENTITY, SP_ENTITY, "ada@corp");
        final SamlProviderConfig config = config(idpCertPem, SP_ENTITY);

        validator.validate(config, response, "relay"); // first use accepted

        assertThatThrownBy(() -> validator.validate(config, response, "relay")) // same assertion again
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("replay");
    }

    // --- helpers -------------------------------------------------------------------------------

    private static SamlProviderConfig config(final String certPem, final String spEntity) {
        return new SamlProviderConfig("corp-saml", "Corp SAML", "https://idp.corp/sso", IDP_ENTITY,
                spEntity, "https://helix.test/acs", certPem, "mail", "givenName", "sn");
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

    @SuppressWarnings("unchecked")
    private static <T> T build(final QName qname) {
        final XMLObjectBuilderFactory bf = XMLObjectProviderRegistrySupport.getBuilderFactory();
        return (T) bf.getBuilder(qname).buildObject(qname);
    }

    private static String signedResponse(final KeyPair key, final X509Certificate cert, final String issuer,
                                         final String audience, final String subject) throws Exception {
        final Issuer respIssuer = build(Issuer.DEFAULT_ELEMENT_NAME);
        respIssuer.setValue(issuer);

        final NameID nameId = build(NameID.DEFAULT_ELEMENT_NAME);
        nameId.setValue(subject);
        final Subject sub = build(Subject.DEFAULT_ELEMENT_NAME);
        sub.setNameID(nameId);

        final Audience aud = build(Audience.DEFAULT_ELEMENT_NAME);
        aud.setURI(audience);
        final AudienceRestriction audRestriction = build(AudienceRestriction.DEFAULT_ELEMENT_NAME);
        audRestriction.getAudiences().add(aud);
        final Conditions conditions = build(Conditions.DEFAULT_ELEMENT_NAME);
        conditions.setNotBefore(Instant.now().minus(5, ChronoUnit.MINUTES));
        conditions.setNotOnOrAfter(Instant.now().plus(5, ChronoUnit.MINUTES));
        conditions.getAudienceRestrictions().add(audRestriction);

        final XSString mailValue = (XSString) XMLObjectProviderRegistrySupport.getBuilderFactory()
                .getBuilder(XSString.TYPE_NAME).buildObject(AttributeValue.DEFAULT_ELEMENT_NAME, XSString.TYPE_NAME);
        mailValue.setValue(subject);
        final Attribute mail = build(Attribute.DEFAULT_ELEMENT_NAME);
        mail.setName("mail");
        mail.getAttributeValues().add(mailValue);
        final AttributeStatement attrStatement = build(AttributeStatement.DEFAULT_ELEMENT_NAME);
        attrStatement.getAttributes().add(mail);

        final Issuer assertionIssuer = build(Issuer.DEFAULT_ELEMENT_NAME);
        assertionIssuer.setValue(issuer);
        final Assertion assertion = build(Assertion.DEFAULT_ELEMENT_NAME);
        assertion.setIssuer(assertionIssuer);
        assertion.setIssueInstant(Instant.now());
        assertion.setID("_a" + System.nanoTime());
        assertion.setSubject(sub);
        assertion.setConditions(conditions);
        assertion.getAttributeStatements().add(attrStatement);

        final Response response = build(Response.DEFAULT_ELEMENT_NAME);
        response.setIssuer(respIssuer);
        response.setID("_r" + System.nanoTime());
        response.setIssueInstant(Instant.now());
        response.getAssertions().add(assertion);

        final BasicX509Credential signingCredential = new BasicX509Credential(cert, (PrivateKey) key.getPrivate());
        final Signature signature = build(Signature.DEFAULT_ELEMENT_NAME);
        signature.setSigningCredential(signingCredential);
        signature.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256);
        signature.setCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
        response.setSignature(signature);

        XMLObjectProviderRegistrySupport.getMarshallerFactory().getMarshaller(response).marshall(response);
        Signer.signObject(signature);

        final String xml = SerializeSupport.nodeToString(response.getDOM());
        return Base64.getEncoder().encodeToString(xml.getBytes(java.nio.charset.StandardCharsets.UTF_8));
    }
}
