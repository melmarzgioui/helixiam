/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.saml;

import net.shibboleth.shared.xml.SerializeSupport;
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
import org.opensaml.saml.saml2.core.Status;
import org.opensaml.saml.saml2.core.StatusCode;
import org.opensaml.saml.saml2.core.Subject;
import org.opensaml.saml.saml2.core.SubjectConfirmation;
import org.opensaml.saml.saml2.core.SubjectConfirmationData;
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
    private static final String ACS_URL = "https://helix.test/acs";

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

    // --- pentest SAML-1 / S-H1 / S-H2 / SAML-3 remediation --------------------------------------

    @Test
    void rejectsAnAssertionWithNoConditionsNotOnOrAfter() throws Exception {
        // SAML-1: an assertion with no enforceable expiry must be rejected (was: accepted + replayable).
        final String response = signedResponse(
                new ResponseSpec(idpKey, idpCert, IDP_ENTITY, SP_ENTITY, "ada@corp").conditionsExpiry(false));
        final SamlProviderConfig config = config(idpCertPem, SP_ENTITY);

        assertThatThrownBy(() -> validator.validate(config, response, "relay"))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("NotOnOrAfter");
    }

    @Test
    void aNoExpiryAssertionCannotBeReplayed() throws Exception {
        // SAML-1 + replay-cache fail-closed: even the FIRST use is rejected, so it can never replay.
        final String first = signedResponse(
                new ResponseSpec(idpKey, idpCert, IDP_ENTITY, SP_ENTITY, "ada@corp").conditionsExpiry(false));
        final SamlProviderConfig config = config(idpCertPem, SP_ENTITY);

        assertThatThrownBy(() -> validator.validate(config, first, "relay"))
                .isInstanceOf(IllegalStateException.class);
        // A distinct no-expiry assertion is likewise rejected — never a "first-seen accept".
        final String second = signedResponse(
                new ResponseSpec(idpKey, idpCert, IDP_ENTITY, SP_ENTITY, "ada@corp").conditionsExpiry(false));
        assertThatThrownBy(() -> validator.validate(config, second, "relay"))
                .isInstanceOf(IllegalStateException.class);
    }

    @Test
    void rejectsAnAssertionWithoutABearerSubjectConfirmation() throws Exception {
        // S-H1: a bearer SubjectConfirmation is mandatory (binds the assertion to this SP).
        final String response = signedResponse(
                new ResponseSpec(idpKey, idpCert, IDP_ENTITY, SP_ENTITY, "ada@corp").bearerConfirmation(false));
        final SamlProviderConfig config = config(idpCertPem, SP_ENTITY);

        assertThatThrownBy(() -> validator.validate(config, response, "relay"))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("SubjectConfirmation");
    }

    @Test
    void rejectsAnAssertionWhoseRecipientIsNotOurAcs() throws Exception {
        // S-H1: Recipient must equal our ACS — a bearer assertion minted for another SP is rejected.
        final String response = signedResponse(
                new ResponseSpec(idpKey, idpCert, IDP_ENTITY, SP_ENTITY, "ada@corp")
                        .recipient("https://another-sp.example/acs"));
        final SamlProviderConfig config = config(idpCertPem, SP_ENTITY);

        assertThatThrownBy(() -> validator.validate(config, response, "relay"))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("SubjectConfirmation");
    }

    @Test
    void rejectsAnAssertionWhoseOwnIssuerDiffers() throws Exception {
        // S-H2: the assertion's OWN Issuer must match the configured IdP entityId (defense in depth).
        final String response = signedResponse(
                new ResponseSpec(idpKey, idpCert, IDP_ENTITY, SP_ENTITY, "attacker@evil")
                        .assertionIssuer("https://evil.attacker/idp"));
        final SamlProviderConfig config = config(idpCertPem, SP_ENTITY);

        assertThatThrownBy(() -> validator.validate(config, response, "relay"))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("issuer mismatch");
    }

    @Test
    void rejectsAResponseWhoseStatusIsNotSuccess() throws Exception {
        // SAML-3: a non-Success Response must not log the user in even if it still carries an assertion.
        final String response = signedResponse(
                new ResponseSpec(idpKey, idpCert, IDP_ENTITY, SP_ENTITY, "victim@corp")
                        .statusCode("urn:oasis:names:tc:SAML:2.0:status:AuthnFailed"));
        final SamlProviderConfig config = config(idpCertPem, SP_ENTITY);

        assertThatThrownBy(() -> validator.validate(config, response, "relay"))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("status is not Success");
    }

    @Test
    void acceptsAValidUnsolicitedAssertionWithNoInResponseTo() throws Exception {
        // IdP-initiated (unsolicited) SSO: no InResponseTo. Must still be accepted — we do NOT
        // unconditionally require InResponseTo (that would break IdP-initiated flows).
        final String response = signedResponse(
                new ResponseSpec(idpKey, idpCert, IDP_ENTITY, SP_ENTITY, "ada@corp").inResponseTo(null));
        final SamlProviderConfig config = config(idpCertPem, SP_ENTITY);

        final SamlAssertionValidator.ValidatedAssertion assertion = validator.validate(config, response, "relay");
        assertThat(assertion.nameId()).isEqualTo("ada@corp");
    }

    @Test
    void acceptsAValidSolicitedAssertionCarryingAnInResponseTo() throws Exception {
        // SP-initiated: an InResponseTo is present. Accepted (binding to the request id is a documented
        // TODO pending outbound-request-id tracking; presence alone must not cause rejection).
        final String response = signedResponse(
                new ResponseSpec(idpKey, idpCert, IDP_ENTITY, SP_ENTITY, "ada@corp").inResponseTo("_req-123"));
        final SamlProviderConfig config = config(idpCertPem, SP_ENTITY);

        final SamlAssertionValidator.ValidatedAssertion assertion = validator.validate(config, response, "relay");
        assertThat(assertion.nameId()).isEqualTo("ada@corp");
    }

    // --- helpers -------------------------------------------------------------------------------

    private static SamlProviderConfig config(final String certPem, final String spEntity) {
        return new SamlProviderConfig("corp-saml", "Corp SAML", "https://idp.corp/sso", IDP_ENTITY,
                spEntity, ACS_URL, certPem, "mail", "givenName", "sn");
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
        return signedResponse(new ResponseSpec(key, cert, issuer, audience, subject));
    }

    /**
     * Options for a signed SAML Response. Defaults describe a spec-compliant Web-SSO-profile response
     * (Status=Success, a bearer SubjectConfirmation with Recipient=ACS + future NotOnOrAfter, and a
     * Conditions/NotOnOrAfter). Individual tests flip one knob to exercise a single rejection path.
     */
    private static final class ResponseSpec {
        private final KeyPair key;
        private final X509Certificate cert;
        private final String issuer;              // both Response and Assertion issuer by default
        private final String audience;
        private final String subject;
        private String assertionIssuer;           // override the assertion's OWN issuer (S-H2)
        private String recipient = ACS_URL;       // bearer SubjectConfirmationData/@Recipient
        private String statusCode = StatusCode.SUCCESS;
        private boolean conditionsExpiry = true;  // set Conditions/@NotOnOrAfter (SAML-1)
        private boolean bearerConfirmation = true; // include a bearer SubjectConfirmation (S-H1)
        private String inResponseTo;              // null = unsolicited/IdP-initiated

        private ResponseSpec(final KeyPair key, final X509Certificate cert, final String issuer,
                             final String audience, final String subject) {
            this.key = key;
            this.cert = cert;
            this.issuer = issuer;
            this.audience = audience;
            this.subject = subject;
            this.assertionIssuer = issuer;
        }

        private ResponseSpec assertionIssuer(final String v) { this.assertionIssuer = v; return this; }
        private ResponseSpec recipient(final String v) { this.recipient = v; return this; }
        private ResponseSpec statusCode(final String v) { this.statusCode = v; return this; }
        private ResponseSpec conditionsExpiry(final boolean v) { this.conditionsExpiry = v; return this; }
        private ResponseSpec bearerConfirmation(final boolean v) { this.bearerConfirmation = v; return this; }
        private ResponseSpec inResponseTo(final String v) { this.inResponseTo = v; return this; }
    }

    private static String signedResponse(final ResponseSpec spec) throws Exception {
        final Issuer respIssuer = build(Issuer.DEFAULT_ELEMENT_NAME);
        respIssuer.setValue(spec.issuer);

        final NameID nameId = build(NameID.DEFAULT_ELEMENT_NAME);
        nameId.setValue(spec.subject);
        final Subject sub = build(Subject.DEFAULT_ELEMENT_NAME);
        sub.setNameID(nameId);
        if (spec.bearerConfirmation) {
            final SubjectConfirmationData scd = build(SubjectConfirmationData.DEFAULT_ELEMENT_NAME);
            scd.setRecipient(spec.recipient);
            scd.setNotOnOrAfter(Instant.now().plus(5, ChronoUnit.MINUTES));
            if (spec.inResponseTo != null) {
                scd.setInResponseTo(spec.inResponseTo);
            }
            final SubjectConfirmation sc = build(SubjectConfirmation.DEFAULT_ELEMENT_NAME);
            sc.setMethod(SubjectConfirmation.METHOD_BEARER);
            sc.setSubjectConfirmationData(scd);
            sub.getSubjectConfirmations().add(sc);
        }

        final Audience aud = build(Audience.DEFAULT_ELEMENT_NAME);
        aud.setURI(spec.audience);
        final AudienceRestriction audRestriction = build(AudienceRestriction.DEFAULT_ELEMENT_NAME);
        audRestriction.getAudiences().add(aud);
        final Conditions conditions = build(Conditions.DEFAULT_ELEMENT_NAME);
        conditions.setNotBefore(Instant.now().minus(5, ChronoUnit.MINUTES));
        if (spec.conditionsExpiry) {
            conditions.setNotOnOrAfter(Instant.now().plus(5, ChronoUnit.MINUTES));
        }
        conditions.getAudienceRestrictions().add(audRestriction);

        final XSString mailValue = (XSString) XMLObjectProviderRegistrySupport.getBuilderFactory()
                .getBuilder(XSString.TYPE_NAME).buildObject(AttributeValue.DEFAULT_ELEMENT_NAME, XSString.TYPE_NAME);
        mailValue.setValue(spec.subject);
        final Attribute mail = build(Attribute.DEFAULT_ELEMENT_NAME);
        mail.setName("mail");
        mail.getAttributeValues().add(mailValue);
        final AttributeStatement attrStatement = build(AttributeStatement.DEFAULT_ELEMENT_NAME);
        attrStatement.getAttributes().add(mail);

        final Issuer assertionIssuer = build(Issuer.DEFAULT_ELEMENT_NAME);
        assertionIssuer.setValue(spec.assertionIssuer);
        final Assertion assertion = build(Assertion.DEFAULT_ELEMENT_NAME);
        assertion.setIssuer(assertionIssuer);
        assertion.setIssueInstant(Instant.now());
        assertion.setID("_a" + System.nanoTime());
        assertion.setSubject(sub);
        assertion.setConditions(conditions);
        assertion.getAttributeStatements().add(attrStatement);

        final StatusCode code = build(StatusCode.DEFAULT_ELEMENT_NAME);
        code.setValue(spec.statusCode);
        final Status status = build(Status.DEFAULT_ELEMENT_NAME);
        status.setStatusCode(code);

        final Response response = build(Response.DEFAULT_ELEMENT_NAME);
        response.setIssuer(respIssuer);
        response.setStatus(status);
        response.setID("_r" + System.nanoTime());
        response.setIssueInstant(Instant.now());
        response.getAssertions().add(assertion);

        final KeyPair key = spec.key;
        final X509Certificate cert = spec.cert;

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
