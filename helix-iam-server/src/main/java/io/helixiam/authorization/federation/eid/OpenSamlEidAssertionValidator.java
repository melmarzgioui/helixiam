/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.eid;

import io.helixiam.authorization.federation.saml.SamlAssertionReplayCache;
import net.shibboleth.shared.xml.ParserPool;
import org.opensaml.core.config.InitializationService;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.Unmarshaller;
import org.opensaml.saml.common.SAMLObject;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.Attribute;
import org.opensaml.saml.saml2.core.AttributeStatement;
import org.opensaml.saml.saml2.core.Audience;
import org.opensaml.saml.saml2.core.AudienceRestriction;
import org.opensaml.saml.saml2.core.AuthnStatement;
import org.opensaml.saml.saml2.core.Conditions;
import org.opensaml.saml.saml2.core.EncryptedAttribute;
import org.opensaml.saml.saml2.core.NameID;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.core.Status;
import org.opensaml.saml.saml2.core.StatusCode;
import org.opensaml.saml.saml2.core.Subject;
import org.opensaml.saml.saml2.encryption.Decrypter;
import org.opensaml.saml.security.impl.SAMLSignatureProfileValidator;
import org.opensaml.security.x509.BasicX509Credential;
import org.opensaml.xmlsec.encryption.support.EncryptedKeyResolver;
import org.opensaml.xmlsec.encryption.support.InlineEncryptedKeyResolver;
import org.opensaml.xmlsec.keyinfo.impl.StaticKeyInfoCredentialResolver;
import org.opensaml.xmlsec.signature.Signature;
import org.opensaml.xmlsec.signature.support.SignatureValidator;
import org.springframework.stereotype.Component;
import org.w3c.dom.Element;

import java.io.ByteArrayInputStream;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Helix IAM E6: production {@link EidAssertionValidator} backed by OpenSAML, matching the real
 * DigiD / eHerkenning shape — a <b>signed cleartext assertion</b> whose subject identifier (BSN /
 * KvK number) is an <b>{@code EncryptedID}</b> (so it never travels in clear), with any sensitive
 * attributes as {@code EncryptedAttribute}. It verifies every present signature (Response and/or
 * Assertion) against the IdP cert, checks issuer / audience / validity-window / replay, decrypts the
 * subject (and encrypted attributes) with the SP key, enforces the minimum {@link EidLevelOfAssurance},
 * and returns the subject id + its NameQualifier type + LoA + attributes.
 *
 * <p>Decryption is algorithm-agnostic (OpenSAML reads the data + key-transport algorithm from the
 * ciphertext), so this serves both DigiD (RSA-OAEP/SHA-256) and eHerkenning (RSA-OAEP-MGF1P/SHA-1).
 */
@Component
public class OpenSamlEidAssertionValidator implements EidAssertionValidator {

    private static final long CLOCK_SKEW_MILLIS = 60_000L;

    private final SamlAssertionReplayCache replayCache;

    static {
        try {
            InitializationService.initialize();
        } catch (final Exception e) {
            throw new IllegalStateException("Failed to initialize OpenSAML", e);
        }
    }

    public OpenSamlEidAssertionValidator(final SamlAssertionReplayCache replayCache) {
        this.replayCache = replayCache;
    }

    @Override
    public EidAssertion validate(final EidProviderConfig config, final String samlResponseBase64,
                                 final String expectedRelayState) {
        try {
            final Response response = parse(samlResponseBase64);
            // Pentest DEEP-1 / SAML-3: reject unless the Response status is Success BEFORE consuming any
            // assertion — a signed assertion inside an AuthnFailed response must not log the user in. (Ported
            // from OpenSamlAssertionValidator.verifyStatusSuccess, which the generic path already had.)
            verifyStatusSuccess(response, config);
            if (response.getAssertions().isEmpty()) {
                throw new IllegalStateException("eID response has no assertion for provider " + config.alias());
            }
            final Assertion assertion = response.getAssertions().get(0);

            if (assertion.getIssuer() == null || !config.idpEntityId().equals(assertion.getIssuer().getValue())) {
                throw new IllegalStateException("eID assertion issuer mismatch for provider " + config.alias());
            }
            verifySignatures(response, assertion, config);
            verifyConditions(assertion, config);
            verifyNotReplayed(assertion, config);

            final String classRef = authnContextClassRef(assertion);
            if (!EidLevelOfAssurance.meetsMinimum(config.scheme(), classRef, config.minimumLoa())) {
                throw new IllegalStateException("eID assertion level of assurance " + classRef
                        + " is below the required " + config.minimumLoa() + " for provider " + config.alias());
            }

            // Build the decrypter only when something is actually encrypted (DigiD/eHerkenning use an
            // EncryptedID + optional EncryptedAttribute; eIDAS is cleartext attribute-based).
            final Decrypter decrypter = needsDecryption(assertion) ? buildDecrypter(config) : null;
            final Map<String, String> attributes = attributes(assertion, decrypter);

            final EidAssertion.Representation representation = representation(config, attributes);

            // eIDAS carries the subject in the PersonIdentifier ATTRIBUTE; DigiD/eHerkenning in the
            // (decrypted) subject NameID. config.subjectAttribute() selects the attribute path.
            if (config.subjectAttribute() != null && !config.subjectAttribute().isBlank()) {
                final String subjectId = attributes.get(config.subjectAttribute());
                if (subjectId == null || subjectId.isBlank()) {
                    throw new IllegalStateException("eID assertion missing subject attribute "
                            + config.subjectAttribute() + " for provider " + config.alias());
                }
                return new EidAssertion(subjectId, config.subjectAttribute(), classRef, attributes, representation);
            }
            final NameID subjectName = subjectNameId(assertion, decrypter, config);
            return new EidAssertion(subjectName.getValue(), subjectName.getNameQualifier(), classRef, attributes, representation);
        } catch (final IllegalStateException e) {
            throw e;
        } catch (final Exception e) {
            throw new IllegalStateException("eID validation failed for provider " + config.alias() + ": " + e.getMessage(), e);
        }
    }

    /** SAML-3 / DEEP-1: the Response status MUST be Success before any assertion is trusted. */
    private void verifyStatusSuccess(final Response response, final EidProviderConfig config) {
        final Status status = response.getStatus();
        final StatusCode code = status != null ? status.getStatusCode() : null;
        if (code == null || !StatusCode.SUCCESS.equals(code.getValue())) {
            throw new IllegalStateException("eID response status is not Success for provider " + config.alias());
        }
    }

    private Response parse(final String samlResponseBase64) throws Exception {
        final byte[] xml = Base64.getDecoder().decode(samlResponseBase64);
        final ParserPool parserPool = XMLObjectProviderRegistrySupport.getParserPool();
        final Element element = parserPool.parse(new ByteArrayInputStream(xml)).getDocumentElement();
        final Unmarshaller unmarshaller = XMLObjectProviderRegistrySupport.getUnmarshallerFactory().getUnmarshaller(element);
        return (Response) unmarshaller.unmarshall(element);
    }

    /** Verify every signature present (Response and/or Assertion); require at least one. */
    private void verifySignatures(final Response response, final Assertion assertion,
                                  final EidProviderConfig config) throws Exception {
        final BasicX509Credential credential = new BasicX509Credential(parseCertificate(config.idpSigningCertificate()));
        final List<Signature> signatures = new ArrayList<>();
        if (response.getSignature() != null) {
            signatures.add(response.getSignature());
        }
        if (assertion.getSignature() != null) {
            signatures.add(assertion.getSignature());
        }
        if (signatures.isEmpty()) {
            throw new IllegalStateException("eID response/assertion is not signed for provider " + config.alias());
        }
        for (final Signature signature : signatures) {
            new SAMLSignatureProfileValidator().validate(signature);
            SignatureValidator.validate(signature, credential);
        }
    }

    private void verifyConditions(final Assertion assertion, final EidProviderConfig config) {
        final Conditions conditions = assertion.getConditions();
        if (conditions == null) {
            throw new IllegalStateException("eID assertion has no conditions for provider " + config.alias());
        }
        final long now = Instant.now().toEpochMilli();
        if (conditions.getNotBefore() != null && now + CLOCK_SKEW_MILLIS < conditions.getNotBefore().toEpochMilli()) {
            throw new IllegalStateException("eID assertion not yet valid for provider " + config.alias());
        }
        if (conditions.getNotOnOrAfter() != null && now - CLOCK_SKEW_MILLIS >= conditions.getNotOnOrAfter().toEpochMilli()) {
            throw new IllegalStateException("eID assertion expired for provider " + config.alias());
        }
        final boolean audienceOk = conditions.getAudienceRestrictions().stream()
                .map(AudienceRestriction::getAudiences)
                .flatMap(List::stream)
                .map(Audience::getURI)
                .anyMatch(uri -> config.spEntityId().equals(uri));
        if (!audienceOk) {
            throw new IllegalStateException("eID assertion audience does not include " + config.spEntityId());
        }
    }

    private void verifyNotReplayed(final Assertion assertion, final EidProviderConfig config) {
        final String id = assertion.getID();
        if (id == null || id.isBlank()) {
            throw new IllegalStateException("eID assertion has no ID for provider " + config.alias());
        }
        final Conditions conditions = assertion.getConditions();
        final Instant expiresAt = conditions != null ? conditions.getNotOnOrAfter() : null;
        if (!replayCache.checkAndRecord(id, expiresAt)) {
            throw new IllegalStateException("eID assertion replay detected for provider " + config.alias());
        }
    }

    /** Build the representation (mandate) context from the configured attribute names, if any. */
    private static EidAssertion.Representation representation(final EidProviderConfig config,
                                                             final Map<String, String> attributes) {
        final EidProviderConfig.Representation rep = config.representation();
        if (rep == null) {
            return null;
        }
        final String actingSubjectId = rep.actingSubjectAttribute() == null ? null
                : attributes.get(rep.actingSubjectAttribute());
        final String serviceId = rep.serviceIdAttribute() == null ? null : attributes.get(rep.serviceIdAttribute());
        if (actingSubjectId == null && serviceId == null) {
            return null; // representation configured but the IdP asserted none
        }
        return new EidAssertion.Representation(actingSubjectId, serviceId);
    }

    private static boolean needsDecryption(final Assertion assertion) {
        final boolean encryptedSubject = assertion.getSubject() != null && assertion.getSubject().getEncryptedID() != null;
        final boolean encryptedAttrs = assertion.getAttributeStatements().stream()
                .anyMatch(statement -> !statement.getEncryptedAttributes().isEmpty());
        return encryptedSubject || encryptedAttrs;
    }

    private static String authnContextClassRef(final Assertion assertion) {
        for (final AuthnStatement statement : assertion.getAuthnStatements()) {
            if (statement.getAuthnContext() != null && statement.getAuthnContext().getAuthnContextClassRef() != null) {
                return statement.getAuthnContext().getAuthnContextClassRef().getURI();
            }
        }
        return null;
    }

    /** The subject NameID — decrypted from the {@code EncryptedID} when present (DigiD/eHerkenning). */
    private static NameID subjectNameId(final Assertion assertion, final Decrypter decrypter,
                                        final EidProviderConfig config) throws Exception {
        final Subject subject = assertion.getSubject();
        if (subject == null) {
            throw new IllegalStateException("eID assertion has no subject for provider " + config.alias());
        }
        if (subject.getEncryptedID() != null) {
            final SAMLObject decrypted = decrypter.decrypt(subject.getEncryptedID());
            if (!(decrypted instanceof NameID nameId)) {
                throw new IllegalStateException("eID EncryptedID did not decrypt to a NameID for provider " + config.alias());
            }
            return nameId;
        }
        if (subject.getNameID() != null) {
            return subject.getNameID();
        }
        throw new IllegalStateException("eID assertion has no subject identifier for provider " + config.alias());
    }

    private static Map<String, String> attributes(final Assertion assertion, final Decrypter decrypter) throws Exception {
        final Map<String, String> attributes = new LinkedHashMap<>();
        for (final AttributeStatement statement : assertion.getAttributeStatements()) {
            for (final Attribute attribute : statement.getAttributes()) {
                putAttribute(attributes, attribute);
            }
            for (final EncryptedAttribute encrypted : statement.getEncryptedAttributes()) {
                putAttribute(attributes, decrypter.decrypt(encrypted));
            }
        }
        return new HashMap<>(attributes);
    }

    private static void putAttribute(final Map<String, String> attributes, final Attribute attribute) {
        if (attribute != null && attribute.getName() != null && !attribute.getAttributeValues().isEmpty()) {
            final Element dom = attribute.getAttributeValues().get(0).getDOM();
            if (dom != null) {
                attributes.put(attribute.getName(), dom.getTextContent());
            }
        }
    }

    private static Decrypter buildDecrypter(final EidProviderConfig config) throws Exception {
        final X509Certificate spCert = parseCertificate(config.spSigningCertificate());
        if (spCert == null) {
            throw new IllegalStateException("eID provider " + config.alias()
                    + " requires the SP certificate (spSigningCertificate) alongside the decryption key");
        }
        final PrivateKey spKey = parsePrivateKey(config.spDecryptionPrivateKey());
        final BasicX509Credential credential = new BasicX509Credential(spCert, spKey);
        final StaticKeyInfoCredentialResolver keyResolver = new StaticKeyInfoCredentialResolver(credential);
        final EncryptedKeyResolver encryptedKeyResolver = new InlineEncryptedKeyResolver();
        final Decrypter decrypter = new Decrypter(null, keyResolver, encryptedKeyResolver);
        decrypter.setRootInNewDocument(true);
        return decrypter;
    }

    private static X509Certificate parseCertificate(final String pem) throws Exception {
        if (pem == null || pem.isBlank()) {
            return null;
        }
        final String base64 = pem.replace("-----BEGIN CERTIFICATE-----", "")
                .replace("-----END CERTIFICATE-----", "").replaceAll("\\s", "");
        final byte[] der = Base64.getDecoder().decode(base64);
        return (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(der));
    }

    private static PrivateKey parsePrivateKey(final String pem) throws Exception {
        final String base64 = pem.replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "").replaceAll("\\s", "");
        final byte[] der = Base64.getDecoder().decode(base64);
        return KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(der));
    }
}
