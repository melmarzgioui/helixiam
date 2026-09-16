package group.mfnr.authorization.federation.eid;

import group.mfnr.authorization.federation.saml.InMemorySamlAssertionReplayCache;
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
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.AuthnContext;
import org.opensaml.saml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml.saml2.core.AuthnStatement;
import org.opensaml.saml.saml2.core.AttributeStatement;
import org.opensaml.saml.saml2.core.Audience;
import org.opensaml.saml.saml2.core.AudienceRestriction;
import org.opensaml.saml.saml2.core.Conditions;
import org.opensaml.saml.saml2.core.EncryptedID;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.core.NameID;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.core.Subject;
import org.opensaml.saml.saml2.encryption.Encrypter;
import org.opensaml.security.x509.BasicX509Credential;
import org.opensaml.xmlsec.encryption.support.DataEncryptionParameters;
import org.opensaml.xmlsec.encryption.support.EncryptionConstants;
import org.opensaml.xmlsec.encryption.support.KeyEncryptionParameters;
import org.opensaml.xmlsec.keyinfo.impl.X509KeyInfoGeneratorFactory;
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
 * Helix IAM E6: live validation of {@link OpenSamlEidAssertionValidator} in the real DigiD shape — a
 * signed cleartext assertion whose subject is an {@code EncryptedID} (the BSN, with NameQualifier
 * {@code urn:nl-eid-gdi:1.0:id:legacy-BSN}), AES-256 data key wrapped with RSA-OAEP to the SP cert.
 * Proves the validator verifies the IdP signature, decrypts the BSN with the SP key, returns the
 * subject + type + LoA, and rejects a below-minimum LoA and an unknown-cert signature. Fully offline.
 */
class OpenSamlEidAssertionValidatorIntegrationTest {

    private static final String IDP_ENTITY = "https://digid.example/entity";
    private static final String SP_ENTITY = "https://helix.test/sp";
    private static final String BSN = "123456782";
    private static final String LEGACY_BSN = "urn:nl-eid-gdi:1.0:id:legacy-BSN";
    private static final String PERSISTENT = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent";
    private static final String DIGID_MIDDEN = "urn:nl-eid-gdi:1.0:LoA:Midden";
    private static final String DIGID_SUBSTANTIAL = "urn:nl-eid-gdi:1.0:LoA:Substantial";
    private static final String DIGID_HIGH = "urn:nl-eid-gdi:1.0:LoA:High";

    private static KeyPair idpKey;
    private static X509Certificate idpCert;
    private static String idpCertPem;
    private static KeyPair spKey;
    private static X509Certificate spCert;
    private static String spKeyPem;
    private static String spCertPem;

    private final OpenSamlEidAssertionValidator validator =
            new OpenSamlEidAssertionValidator(new InMemorySamlAssertionReplayCache());

    @BeforeAll
    static void init() throws Exception {
        InitializationService.initialize();
        idpKey = rsa();
        idpCert = selfSigned(idpKey, "CN=DigiD");
        idpCertPem = pem(idpCert);
        spKey = rsa();
        spCert = selfSigned(spKey, "CN=HelixSP");
        spKeyPem = pkcs8Pem(spKey.getPrivate());
        spCertPem = pem(spCert);
    }

    @Test
    void verifiesDecryptsAndReturnsTheBsnTypeAndLoa() throws Exception {
        final String response = signedResponseWithEncryptedId(idpKey, idpCert, BSN, LEGACY_BSN, DIGID_SUBSTANTIAL);
        final EidProviderConfig config = config(DIGID_MIDDEN); // require Midden; got Substantieel

        final EidAssertion assertion = validator.validate(config, response, "relay");

        assertThat(assertion.subjectId()).isEqualTo(BSN);
        assertThat(assertion.subjectType()).isEqualTo(LEGACY_BSN);
        assertThat(assertion.authnContextClassRef()).isEqualTo(DIGID_SUBSTANTIAL);
    }

    @Test
    void rejectsAnAssertionBelowTheRequiredLevelOfAssurance() throws Exception {
        final String response = signedResponseWithEncryptedId(idpKey, idpCert, BSN, LEGACY_BSN, DIGID_SUBSTANTIAL);
        final EidProviderConfig config = config(DIGID_HIGH); // require Hoog; got only Substantieel

        assertThatThrownBy(() -> validator.validate(config, response, "relay"))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("assurance");
    }

    @Test
    void rejectsAnAssertionSignedByAnUnknownCertificate() throws Exception {
        final KeyPair foreign = rsa();
        final String response = signedResponseWithEncryptedId(foreign, selfSigned(foreign, "CN=Evil"), BSN, LEGACY_BSN, DIGID_SUBSTANTIAL);
        final EidProviderConfig config = config(DIGID_MIDDEN); // expects the genuine DigiD cert

        assertThatThrownBy(() -> validator.validate(config, response, "relay"))
                .isInstanceOf(IllegalStateException.class);
    }

    @Test
    void eherkenningDecryptsTheKvkNumberFromTheEncryptedId() throws Exception {
        final String kvkNr = "90001354";
        final String kvkType = "urn:etoegang:1.9:EntityConcernedID:KvKnr";
        final String loa3 = "urn:etoegang:core:assurance-class:loa3";
        final String response = signedResponseWithEncryptedId(idpKey, idpCert, kvkNr, kvkType, loa3);
        final EidProviderConfig config = new EidProviderConfig(EidScheme.EHERKENNING, "eherkenning", "eHerkenning",
                "https://eh.example/sso", IDP_ENTITY, SP_ENTITY, "https://helix.test/acs", idpCertPem, spKeyPem,
                null, spCertPem, loa3, null);

        final EidAssertion assertion = validator.validate(config, response, "relay");

        assertThat(assertion.subjectId()).isEqualTo(kvkNr);
        assertThat(assertion.subjectType()).isEqualTo(kvkType);
        assertThat(assertion.authnContextClassRef()).isEqualTo(loa3);
    }

    @Test
    void eidasTakesTheSubjectFromThePersonIdentifierAttribute() throws Exception {
        final String personIdentifier = "NL/BE/123456789";
        final String substantial = "http://eidas.europa.eu/LoA/substantial";
        final String response = signedEidasResponse(idpKey, idpCert, personIdentifier, "Lovelace", substantial);
        final EidProviderConfig config = new EidProviderConfig(EidScheme.EIDAS, "eidas", "eIDAS",
                "https://eidas.example/sso", IDP_ENTITY, SP_ENTITY, "https://helix.test/acs", idpCertPem, spKeyPem,
                null, spCertPem, substantial, "http://eidas.europa.eu/attributes/naturalperson/PersonIdentifier");

        final EidAssertion assertion = validator.validate(config, response, "relay");

        assertThat(assertion.subjectId()).isEqualTo(personIdentifier);
        assertThat(assertion.authnContextClassRef()).isEqualTo(substantial);
        assertThat(assertion.attributes())
                .containsEntry("http://eidas.europa.eu/attributes/naturalperson/CurrentFamilyName", "Lovelace");
    }

    @Test
    void eherkenningRepresentationExtractsTheActingSubjectAndService() throws Exception {
        final String kvkNr = "90001354";
        final String kvkType = "urn:etoegang:1.9:EntityConcernedID:KvKnr";
        final String loa3 = "urn:etoegang:core:assurance-class:loa3";
        final String actingAttr = "urn:etoegang:1.9:ActingSubjectID";
        final String serviceAttr = "urn:etoegang:core:ServiceID";

        // Subject = the represented company (EncryptedID KvK); acting subject + service as attributes.
        final NameID repNameId = build(NameID.DEFAULT_ELEMENT_NAME);
        repNameId.setValue(kvkNr);
        repNameId.setFormat(PERSISTENT);
        repNameId.setNameQualifier(kvkType);
        final Subject subject = build(Subject.DEFAULT_ELEMENT_NAME);
        subject.setEncryptedID(encrypt(repNameId));
        final AttributeStatement attrStatement = build(AttributeStatement.DEFAULT_ELEMENT_NAME);
        attrStatement.getAttributes().add(attribute(actingAttr, "123456782"));   // representative BSN
        attrStatement.getAttributes().add(attribute(serviceAttr, "urn:service:42"));
        final String response = signAndWrap(idpKey, idpCert, subject, attrStatement, loa3);

        final EidProviderConfig config = new EidProviderConfig(EidScheme.EHERKENNING, "eh-rep", "eHerkenning",
                "https://eh.example/sso", IDP_ENTITY, SP_ENTITY, "https://helix.test/acs", idpCertPem, spKeyPem,
                null, spCertPem, loa3, null, EidProviderConfig.Binding.POST,
                new EidProviderConfig.Representation(true, "urn:service:42", actingAttr, serviceAttr));

        final EidAssertion assertion = validator.validate(config, response, "relay");

        assertThat(assertion.subjectId()).isEqualTo(kvkNr); // represented company
        assertThat(assertion.representation()).isNotNull();
        assertThat(assertion.representation().actingSubjectId()).isEqualTo("123456782"); // representative
        assertThat(assertion.representation().serviceId()).isEqualTo("urn:service:42");
    }

    // --- helpers -------------------------------------------------------------------------------

    private static EidProviderConfig config(final String minimumLoa) {
        return new EidProviderConfig(EidScheme.DIGID, "digid", "DigiD", "https://digid.example/sso",
                IDP_ENTITY, SP_ENTITY, "https://helix.test/acs", idpCertPem, spKeyPem,
                null, spCertPem, minimumLoa, null);
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

    @SuppressWarnings("unchecked")
    private static <T> T build(final QName qname) {
        final XMLObjectBuilderFactory bf = XMLObjectProviderRegistrySupport.getBuilderFactory();
        return (T) bf.getBuilder(qname).buildObject(qname);
    }

    /** DigiD/eHerkenning shape: the identifier is an EncryptedID with a scheme NameQualifier. */
    private static String signedResponseWithEncryptedId(final KeyPair idpKeyPair, final X509Certificate idpCertificate,
                                                        final String value, final String nameQualifier,
                                                        final String classRef) throws Exception {
        final NameID nameId = build(NameID.DEFAULT_ELEMENT_NAME);
        nameId.setValue(value);
        nameId.setFormat(PERSISTENT);
        nameId.setNameQualifier(nameQualifier);
        final Subject subject = build(Subject.DEFAULT_ELEMENT_NAME);
        subject.setEncryptedID(encrypt(nameId));
        return signAndWrap(idpKeyPair, idpCertificate, subject, null, classRef);
    }

    /** eIDAS shape: a cleartext signed assertion carrying the PersonIdentifier + names as attributes. */
    private static String signedEidasResponse(final KeyPair idpKeyPair, final X509Certificate idpCertificate,
                                              final String personIdentifier, final String familyName,
                                              final String classRef) throws Exception {
        final NameID nameId = build(NameID.DEFAULT_ELEMENT_NAME);
        nameId.setValue(personIdentifier);
        nameId.setFormat("urn:oasis:names:tc:SAML:2.0:nameid-format:transient");
        final Subject subject = build(Subject.DEFAULT_ELEMENT_NAME);
        subject.setNameID(nameId);

        final AttributeStatement attrStatement = build(AttributeStatement.DEFAULT_ELEMENT_NAME);
        attrStatement.getAttributes().add(attribute(
                "http://eidas.europa.eu/attributes/naturalperson/PersonIdentifier", personIdentifier));
        attrStatement.getAttributes().add(attribute(
                "http://eidas.europa.eu/attributes/naturalperson/CurrentFamilyName", familyName));
        return signAndWrap(idpKeyPair, idpCertificate, subject, attrStatement, classRef);
    }

    private static String signAndWrap(final KeyPair idpKeyPair, final X509Certificate idpCertificate,
                                      final Subject subject, final AttributeStatement attrStatement,
                                      final String classRef) throws Exception {
        final Audience aud = build(Audience.DEFAULT_ELEMENT_NAME);
        aud.setURI(SP_ENTITY);
        final AudienceRestriction audRestriction = build(AudienceRestriction.DEFAULT_ELEMENT_NAME);
        audRestriction.getAudiences().add(aud);
        final Conditions conditions = build(Conditions.DEFAULT_ELEMENT_NAME);
        conditions.setNotBefore(Instant.now().minus(5, ChronoUnit.MINUTES));
        conditions.setNotOnOrAfter(Instant.now().plus(5, ChronoUnit.MINUTES));
        conditions.getAudienceRestrictions().add(audRestriction);

        final AuthnContextClassRef ref = build(AuthnContextClassRef.DEFAULT_ELEMENT_NAME);
        ref.setURI(classRef);
        final AuthnContext authnContext = build(AuthnContext.DEFAULT_ELEMENT_NAME);
        authnContext.setAuthnContextClassRef(ref);
        final AuthnStatement authnStatement = build(AuthnStatement.DEFAULT_ELEMENT_NAME);
        authnStatement.setAuthnInstant(Instant.now());
        authnStatement.setAuthnContext(authnContext);

        final Issuer assertionIssuer = build(Issuer.DEFAULT_ELEMENT_NAME);
        assertionIssuer.setValue(IDP_ENTITY);
        final Assertion assertion = build(Assertion.DEFAULT_ELEMENT_NAME);
        assertion.setIssuer(assertionIssuer);
        assertion.setIssueInstant(Instant.now());
        assertion.setID("_a" + System.nanoTime());
        assertion.setSubject(subject);
        assertion.setConditions(conditions);
        assertion.getAuthnStatements().add(authnStatement);
        if (attrStatement != null) {
            assertion.getAttributeStatements().add(attrStatement);
        }

        // Sign the (cleartext) assertion — the EncryptedID is part of the signed content.
        final BasicX509Credential signingCredential = new BasicX509Credential(idpCertificate, idpKeyPair.getPrivate());
        final Signature signature = build(Signature.DEFAULT_ELEMENT_NAME);
        signature.setSigningCredential(signingCredential);
        signature.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256);
        signature.setCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
        assertion.setSignature(signature);
        XMLObjectProviderRegistrySupport.getMarshallerFactory().getMarshaller(assertion).marshall(assertion);
        Signer.signObject(signature);

        final Issuer respIssuer = build(Issuer.DEFAULT_ELEMENT_NAME);
        respIssuer.setValue(IDP_ENTITY);
        final Response response = build(Response.DEFAULT_ELEMENT_NAME);
        response.setIssuer(respIssuer);
        response.setID("_r" + System.nanoTime());
        response.setIssueInstant(Instant.now());
        response.getAssertions().add(assertion);

        XMLObjectProviderRegistrySupport.getMarshallerFactory().getMarshaller(response).marshall(response);
        final String xml = SerializeSupport.nodeToString(response.getDOM());
        return Base64.getEncoder().encodeToString(xml.getBytes(java.nio.charset.StandardCharsets.UTF_8));
    }

    private static org.opensaml.saml.saml2.core.Attribute attribute(final String name, final String value) {
        final org.opensaml.core.xml.schema.XSString sv = (org.opensaml.core.xml.schema.XSString)
                XMLObjectProviderRegistrySupport.getBuilderFactory()
                        .getBuilder(org.opensaml.core.xml.schema.XSString.TYPE_NAME)
                        .buildObject(org.opensaml.saml.saml2.core.AttributeValue.DEFAULT_ELEMENT_NAME,
                                org.opensaml.core.xml.schema.XSString.TYPE_NAME);
        sv.setValue(value);
        final org.opensaml.saml.saml2.core.Attribute attribute = build(org.opensaml.saml.saml2.core.Attribute.DEFAULT_ELEMENT_NAME);
        attribute.setName(name);
        attribute.setNameFormat("urn:oasis:names:tc:SAML:2.0:attrname-format:uri");
        attribute.getAttributeValues().add(sv);
        return attribute;
    }

    private static EncryptedID encrypt(final NameID nameId) throws Exception {
        final DataEncryptionParameters dataParams = new DataEncryptionParameters();
        dataParams.setAlgorithm(EncryptionConstants.ALGO_ID_BLOCKCIPHER_AES256);

        final X509KeyInfoGeneratorFactory keyInfoFactory = new X509KeyInfoGeneratorFactory();
        keyInfoFactory.setEmitEntityCertificate(true);
        final KeyEncryptionParameters keyParams = new KeyEncryptionParameters();
        keyParams.setEncryptionCredential(new BasicX509Credential(spCert));
        keyParams.setAlgorithm(EncryptionConstants.ALGO_ID_KEYTRANSPORT_RSAOAEP);
        keyParams.setKeyInfoGenerator(keyInfoFactory.newInstance());

        final Encrypter encrypter = new Encrypter(dataParams, keyParams);
        encrypter.setKeyPlacement(Encrypter.KeyPlacement.INLINE);
        return encrypter.encrypt(nameId);
    }
}
