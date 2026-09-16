/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.idp.saml;

import io.helixiam.authorization.amqp.saml.SamlSpOptions;
import net.shibboleth.utilities.java.support.xml.SerializeSupport;
import org.opensaml.core.config.InitializationService;
import org.opensaml.core.xml.XMLObjectBuilderFactory;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.schema.XSString;
import org.opensaml.saml.common.SAMLObjectContentReference;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.Attribute;
import org.opensaml.saml.saml2.core.AttributeStatement;
import org.opensaml.saml.saml2.core.AttributeValue;
import org.opensaml.saml.saml2.core.Audience;
import org.opensaml.saml.saml2.core.AudienceRestriction;
import org.opensaml.saml.saml2.core.AuthnContext;
import org.opensaml.saml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml.saml2.core.AuthnStatement;
import org.opensaml.saml.saml2.core.Conditions;
import org.opensaml.saml.saml2.core.EncryptedAssertion;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.core.NameID;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.core.Status;
import org.opensaml.saml.saml2.core.StatusCode;
import org.opensaml.saml.saml2.core.Subject;
import org.opensaml.saml.saml2.core.SubjectConfirmation;
import org.opensaml.saml.saml2.core.SubjectConfirmationData;
import org.opensaml.saml.saml2.encryption.Encrypter;
import org.opensaml.security.x509.BasicX509Credential;
import org.opensaml.xmlsec.encryption.support.DataEncryptionParameters;
import org.opensaml.xmlsec.encryption.support.EncryptionConstants;
import org.opensaml.xmlsec.encryption.support.KeyEncryptionParameters;
import org.opensaml.xmlsec.keyinfo.impl.X509KeyInfoGeneratorFactory;
import org.opensaml.xmlsec.signature.Signature;
import org.opensaml.xmlsec.signature.support.SignatureConstants;
import org.opensaml.xmlsec.signature.support.Signer;
import org.opensaml.saml.common.SignableSAMLObject;
import org.springframework.stereotype.Component;

import javax.xml.namespace.QName;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Map;
import java.util.UUID;

/**
 * Helix IAM E7.1 + WSO2-class SAML2: issues a signed (optionally encrypted) SAML2 {@code <Response>} for a
 * relying party — Helix acting as a SAML <b>Identity Provider</b>. Per-SP {@link SamlSpOptions} drive what's
 * signed (assertion and/or response), the signature + digest algorithms, the NameID format, whether the
 * assertion is encrypted to the SP's cert, the assertion lifetime, extra audiences, and whether to release
 * an attribute statement. The Web-SSO-profile {@code SubjectConfirmation=bearer} is always emitted.
 */
@Component
public class SamlAssertionIssuer {

    static {
        try {
            InitializationService.initialize();
        } catch (final Exception e) {
            throw new IllegalStateException("Failed to initialize OpenSAML", e);
        }
    }

    /**
     * @param idp                  Helix IdP identity + signing material
     * @param audienceSpEntityId   the RP/SP entity id the assertion is restricted to
     * @param assertionConsumerUrl the SP ACS URL the Response is addressed to (also the bearer Recipient)
     * @param subjectNameId        the authenticated subject's NameID value
     * @param attributes           attribute name → value to assert
     * @param authnContextClassRef the LoA the user authenticated at
     * @param inResponseTo         the SP AuthnRequest ID this answers (null for IdP-initiated)
     * @param options              the SP's WSO2-class advanced SAML options (never null — use defaults())
     * @return the base64-encoded signed SAML Response (for the HTTP-POST ACS form)
     */
    public String issueResponse(final SamlIdpConfig idp, final String audienceSpEntityId,
                                final String assertionConsumerUrl, final String subjectNameId,
                                final Map<String, String> attributes, final String authnContextClassRef,
                                final String inResponseTo, final SamlSpOptions options) {
        final SamlSpOptions o = options == null ? SamlSpOptions.defaults() : options;
        try {
            final Assertion assertion = buildAssertion(idp, audienceSpEntityId, assertionConsumerUrl,
                    subjectNameId, attributes, authnContextClassRef, inResponseTo, o);
            // Sign the assertion (default ON). Must happen before any encryption.
            if (o.signAssertionOrDefault()) {
                signObject(assertion, idp, o);
            }

            final Response response = build(Response.DEFAULT_ELEMENT_NAME);
            response.setID("_r" + UUID.randomUUID());
            response.setIssueInstant(Instant.now());
            response.setDestination(assertionConsumerUrl);
            if (inResponseTo != null && !inResponseTo.isBlank()) {
                response.setInResponseTo(inResponseTo);
            }
            response.setIssuer(issuer(idp.idpEntityId()));
            response.setStatus(successStatus());

            // Encrypt the assertion to the SP's cert when requested, else embed it in the clear.
            if (o.encryptAssertionOrDefault() && o.encryptionCertificate() != null && !o.encryptionCertificate().isBlank()) {
                response.getEncryptedAssertions().add(encrypt(assertion, o.encryptionCertificate()));
            } else {
                response.getAssertions().add(assertion);
            }

            // Optionally sign the outer Response too (WSO2 default-off; some SPs require it).
            if (o.signResponseOrDefault()) {
                signObject(response, idp, o);
            }

            final var marshalled = XMLObjectProviderRegistrySupport.getMarshallerFactory()
                    .getMarshaller(response).marshall(response);
            final String xml = SerializeSupport.nodeToString(marshalled);
            return Base64.getEncoder().encodeToString(xml.getBytes(StandardCharsets.UTF_8));
        } catch (final Exception e) {
            throw new IllegalStateException("Failed to issue SAML response for SP " + audienceSpEntityId, e);
        }
    }

    /**
     * Issue a Response that carries no assertion, only a {@code <Status>} with the given second-level status
     * code (e.g. {@code urn:oasis:names:tc:SAML:2.0:status:NoPassive}). Signed with the IdP key. Used to tell
     * an SP "I can't satisfy this AuthnRequest" — e.g. an {@code IsPassive} request with no active session.
     */
    public String issueStatusResponse(final SamlIdpConfig idp, final String assertionConsumerUrl,
                                      final String inResponseTo, final String secondLevelStatusCode) {
        try {
            final Response response = build(Response.DEFAULT_ELEMENT_NAME);
            response.setID("_r" + UUID.randomUUID());
            response.setIssueInstant(Instant.now());
            response.setDestination(assertionConsumerUrl);
            if (inResponseTo != null && !inResponseTo.isBlank()) {
                response.setInResponseTo(inResponseTo);
            }
            response.setIssuer(issuer(idp.idpEntityId()));
            response.setStatus(responderStatus(secondLevelStatusCode));
            signObject(response, idp, SamlSpOptions.defaults());
            final var marshalled = XMLObjectProviderRegistrySupport.getMarshallerFactory()
                    .getMarshaller(response).marshall(response);
            return Base64.getEncoder().encodeToString(
                    SerializeSupport.nodeToString(marshalled).getBytes(StandardCharsets.UTF_8));
        } catch (final Exception e) {
            throw new IllegalStateException("Failed to issue SAML status response", e);
        }
    }

    private Assertion buildAssertion(final SamlIdpConfig idp, final String audience, final String acsUrl,
                                     final String subjectNameId, final Map<String, String> attributes,
                                     final String authnContextClassRef, final String inResponseTo,
                                     final SamlSpOptions o) {
        final int lifetime = o.assertionLifetimeSecondsOrDefault();
        final Instant notOnOrAfter = Instant.now().plus(lifetime, ChronoUnit.SECONDS);

        final NameID nameId = build(NameID.DEFAULT_ELEMENT_NAME);
        nameId.setValue(subjectNameId);
        nameId.setFormat(o.nameIdFormatOrDefault());

        // SAML Web SSO profile: bearer SubjectConfirmation with Recipient + InResponseTo + NotOnOrAfter.
        final SubjectConfirmationData scd = build(SubjectConfirmationData.DEFAULT_ELEMENT_NAME);
        scd.setRecipient(acsUrl);
        scd.setNotOnOrAfter(notOnOrAfter);
        if (inResponseTo != null && !inResponseTo.isBlank()) {
            scd.setInResponseTo(inResponseTo);
        }
        final SubjectConfirmation sc = build(SubjectConfirmation.DEFAULT_ELEMENT_NAME);
        sc.setMethod(SubjectConfirmation.METHOD_BEARER);
        sc.setSubjectConfirmationData(scd);
        final Subject subject = build(Subject.DEFAULT_ELEMENT_NAME);
        subject.setNameID(nameId);
        subject.getSubjectConfirmations().add(sc);

        final AudienceRestriction audienceRestriction = build(AudienceRestriction.DEFAULT_ELEMENT_NAME);
        audienceRestriction.getAudiences().add(audience(audience));
        for (final String extra : o.extraAudiencesOrEmpty()) {
            audienceRestriction.getAudiences().add(audience(extra));
        }
        final Conditions conditions = build(Conditions.DEFAULT_ELEMENT_NAME);
        conditions.setNotBefore(Instant.now().minus(1, ChronoUnit.MINUTES));
        conditions.setNotOnOrAfter(notOnOrAfter);
        conditions.getAudienceRestrictions().add(audienceRestriction);

        final AuthnContextClassRef classRef = build(AuthnContextClassRef.DEFAULT_ELEMENT_NAME);
        classRef.setURI(authnContextClassRef);
        final AuthnContext authnContext = build(AuthnContext.DEFAULT_ELEMENT_NAME);
        authnContext.setAuthnContextClassRef(classRef);
        final AuthnStatement authnStatement = build(AuthnStatement.DEFAULT_ELEMENT_NAME);
        authnStatement.setAuthnInstant(Instant.now());
        authnStatement.setSessionIndex("_si" + UUID.randomUUID());
        authnStatement.setAuthnContext(authnContext);

        final Assertion assertion = build(Assertion.DEFAULT_ELEMENT_NAME);
        assertion.setID("_a" + UUID.randomUUID());
        assertion.setIssueInstant(Instant.now());
        assertion.setIssuer(issuer(idp.idpEntityId()));
        assertion.setSubject(subject);
        assertion.setConditions(conditions);
        assertion.getAuthnStatements().add(authnStatement);
        if (o.includeAttributesOrDefault() && attributes != null && !attributes.isEmpty()) {
            assertion.getAttributeStatements().add(attributeStatement(attributes));
        }
        return assertion;
    }

    /** Sign a SAML object (assertion or response) with the IdP key + the SP's chosen algorithms. */
    private void signObject(final SignableSAMLObject signable, final SamlIdpConfig idp, final SamlSpOptions o)
            throws Exception {
        final BasicX509Credential credential = new BasicX509Credential(
                parseCertificate(idp.signingCertificate()), parsePrivateKey(idp.signingPrivateKey()));
        final Signature signature = build(Signature.DEFAULT_ELEMENT_NAME);
        signature.setSigningCredential(credential);
        signature.setSignatureAlgorithm(signatureAlgorithm(o.signatureAlgorithmOrDefault()));
        signature.setCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
        signature.setKeyInfo(keyInfo(credential));
        signable.setSignature(signature);
        // Marshalling populates the content reference; set the digest before signing.
        XMLObjectProviderRegistrySupport.getMarshallerFactory().getMarshaller(signable).marshall(signable);
        if (!signature.getContentReferences().isEmpty()
                && signature.getContentReferences().get(0) instanceof SAMLObjectContentReference ref) {
            ref.setDigestAlgorithm(digestAlgorithm(o.digestAlgorithmOrDefault()));
        }
        Signer.signObject(signature);
    }

    private org.opensaml.xmlsec.signature.KeyInfo keyInfo(final BasicX509Credential credential) throws Exception {
        final X509KeyInfoGeneratorFactory kigf = new X509KeyInfoGeneratorFactory();
        kigf.setEmitEntityCertificate(true);
        return kigf.newInstance().generate(credential);
    }

    /** Encrypt an assertion to the SP's cert: AES-256-GCM data key, RSA-OAEP key transport. */
    private EncryptedAssertion encrypt(final Assertion assertion, final String spCertPem) throws Exception {
        final BasicX509Credential spCredential = new BasicX509Credential(parseCertificate(spCertPem));
        final DataEncryptionParameters dataParams = new DataEncryptionParameters();
        dataParams.setAlgorithm(EncryptionConstants.ALGO_ID_BLOCKCIPHER_AES256_GCM);
        final KeyEncryptionParameters kekParams = new KeyEncryptionParameters();
        kekParams.setEncryptionCredential(spCredential);
        kekParams.setAlgorithm(EncryptionConstants.ALGO_ID_KEYTRANSPORT_RSAOAEP);
        final X509KeyInfoGeneratorFactory kigf = new X509KeyInfoGeneratorFactory();
        kigf.setEmitEntityCertificate(true);
        kekParams.setKeyInfoGenerator(kigf.newInstance());
        final Encrypter encrypter = new Encrypter(dataParams, kekParams);
        encrypter.setKeyPlacement(Encrypter.KeyPlacement.PEER);
        return encrypter.encrypt(assertion);
    }

    private static String signatureAlgorithm(final String name) {
        return switch (name == null ? "" : name.toUpperCase()) {
            case "RSA_SHA1" -> SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA1;
            case "RSA_SHA512" -> SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA512;
            default -> SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256;
        };
    }

    private static String digestAlgorithm(final String name) {
        return switch (name == null ? "" : name.toUpperCase()) {
            case "SHA1" -> SignatureConstants.ALGO_ID_DIGEST_SHA1;
            case "SHA512" -> SignatureConstants.ALGO_ID_DIGEST_SHA512;
            default -> SignatureConstants.ALGO_ID_DIGEST_SHA256;
        };
    }

    private static Audience audience(final String uri) {
        final Audience aud = build(Audience.DEFAULT_ELEMENT_NAME);
        aud.setURI(uri);
        return aud;
    }

    private static Issuer issuer(final String entityId) {
        final Issuer issuer = build(Issuer.DEFAULT_ELEMENT_NAME);
        issuer.setValue(entityId);
        return issuer;
    }

    private static Status successStatus() {
        final StatusCode code = build(StatusCode.DEFAULT_ELEMENT_NAME);
        code.setValue(StatusCode.SUCCESS);
        final Status status = build(Status.DEFAULT_ELEMENT_NAME);
        status.setStatusCode(code);
        return status;
    }

    /** A Responder top-level status with a nested second-level code (e.g. NoPassive). */
    private static Status responderStatus(final String secondLevel) {
        final StatusCode nested = build(StatusCode.DEFAULT_ELEMENT_NAME);
        nested.setValue(secondLevel);
        final StatusCode top = build(StatusCode.DEFAULT_ELEMENT_NAME);
        top.setValue(StatusCode.RESPONDER);
        top.setStatusCode(nested);
        final Status status = build(Status.DEFAULT_ELEMENT_NAME);
        status.setStatusCode(top);
        return status;
    }

    private static AttributeStatement attributeStatement(final Map<String, String> attributes) {
        final AttributeStatement statement = build(AttributeStatement.DEFAULT_ELEMENT_NAME);
        attributes.forEach((name, value) -> {
            final XSString xsValue = (XSString) XMLObjectProviderRegistrySupport.getBuilderFactory()
                    .getBuilder(XSString.TYPE_NAME).buildObject(AttributeValue.DEFAULT_ELEMENT_NAME, XSString.TYPE_NAME);
            xsValue.setValue(value);
            final Attribute attribute = build(Attribute.DEFAULT_ELEMENT_NAME);
            attribute.setName(name);
            attribute.setNameFormat("urn:oasis:names:tc:SAML:2.0:attrname-format:uri");
            attribute.getAttributeValues().add(xsValue);
            statement.getAttributes().add(attribute);
        });
        return statement;
    }

    @SuppressWarnings("unchecked")
    private static <T> T build(final QName qname) {
        final XMLObjectBuilderFactory bf = XMLObjectProviderRegistrySupport.getBuilderFactory();
        return (T) bf.getBuilder(qname).buildObject(qname);
    }

    private static X509Certificate parseCertificate(final String pem) throws Exception {
        final String base64 = pem.replace("-----BEGIN CERTIFICATE-----", "")
                .replace("-----END CERTIFICATE-----", "").replaceAll("\\s", "");
        return (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(Base64.getDecoder().decode(base64)));
    }

    private static PrivateKey parsePrivateKey(final String pem) throws Exception {
        final String base64 = pem.replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "").replaceAll("\\s", "");
        return KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(Base64.getDecoder().decode(base64)));
    }
}
