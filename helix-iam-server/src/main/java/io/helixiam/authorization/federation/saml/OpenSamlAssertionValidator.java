/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.saml;

import net.shibboleth.utilities.java.support.xml.ParserPool;
import org.opensaml.core.config.InitializationService;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.Unmarshaller;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.Attribute;
import org.opensaml.saml.saml2.core.AttributeStatement;
import org.opensaml.saml.saml2.core.Audience;
import org.opensaml.saml.saml2.core.AudienceRestriction;
import org.opensaml.saml.saml2.core.Conditions;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.security.impl.SAMLSignatureProfileValidator;
import org.opensaml.security.x509.BasicX509Credential;
import org.opensaml.xmlsec.signature.Signature;
import org.opensaml.xmlsec.signature.support.SignatureValidator;
import org.springframework.stereotype.Component;
import org.w3c.dom.Element;

import java.io.ByteArrayInputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Base64;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Helix IAM E5.2: production {@link SamlAssertionValidator} backed by OpenSAML. Parses the SAMLResponse,
 * verifies the XML signature against the IdP's configured signing certificate (signature-profile +
 * cryptographic validation), and checks the issuer, audience restriction, and the assertion's validity
 * window before returning the NameID + attributes. Any failure throws — the broker treats that as a
 * rejected login. Replaces the fail-closed {@code UnconfiguredSamlAssertionValidator}.
 *
 * <p>Assertion replay is closed by a {@link SamlAssertionReplayCache}: each assertion ID is one-time
 * use within its {@code NotOnOrAfter} window. Signature + audience + time-window + replay are all
 * enforced here.
 */
@Component
public class OpenSamlAssertionValidator implements SamlAssertionValidator {

    private static final long CLOCK_SKEW_MILLIS = 60_000L;

    private final SamlAssertionReplayCache replayCache;

    static {
        try {
            InitializationService.initialize();
        } catch (final Exception e) {
            throw new IllegalStateException("Failed to initialize OpenSAML", e);
        }
    }

    public OpenSamlAssertionValidator(final SamlAssertionReplayCache replayCache) {
        this.replayCache = replayCache;
    }

    @Override
    public ValidatedAssertion validate(final SamlProviderConfig config, final String samlResponseBase64,
                                       final String expectedRelayState) {
        try {
            final Response response = parse(samlResponseBase64);

            if (response.getIssuer() == null || !config.idpEntityId().equals(response.getIssuer().getValue())) {
                throw new IllegalStateException("SAML response issuer mismatch for provider " + config.alias());
            }
            if (response.getAssertions().isEmpty()) {
                throw new IllegalStateException("SAML response has no assertion for provider " + config.alias());
            }
            final Assertion assertion = response.getAssertions().get(0);

            verifySignature(response, assertion, config);
            verifyConditions(assertion, config);
            verifyNotReplayed(assertion, config);

            if (assertion.getSubject() == null || assertion.getSubject().getNameID() == null) {
                throw new IllegalStateException("SAML assertion has no subject NameID for provider " + config.alias());
            }
            return new ValidatedAssertion(assertion.getSubject().getNameID().getValue(), attributes(assertion));
        } catch (final IllegalStateException e) {
            throw e;
        } catch (final Exception e) {
            throw new IllegalStateException("SAML validation failed for provider " + config.alias() + ": " + e.getMessage(), e);
        }
    }

    private Response parse(final String samlResponseBase64) throws Exception {
        final byte[] xml = Base64.getDecoder().decode(samlResponseBase64);
        final ParserPool parserPool = XMLObjectProviderRegistrySupport.getParserPool();
        final Element element = parserPool.parse(new ByteArrayInputStream(xml)).getDocumentElement();
        final Unmarshaller unmarshaller = XMLObjectProviderRegistrySupport.getUnmarshallerFactory().getUnmarshaller(element);
        return (Response) unmarshaller.unmarshall(element);
    }

    /** Require at least one valid signature (on the response or the assertion) by the IdP key. */
    private void verifySignature(final Response response, final Assertion assertion,
                                 final SamlProviderConfig config) throws Exception {
        final BasicX509Credential credential = new BasicX509Credential(parseCertificate(config.idpSigningCertificate()));
        final Signature signature = response.getSignature() != null ? response.getSignature() : assertion.getSignature();
        if (signature == null) {
            throw new IllegalStateException("SAML response/assertion is not signed for provider " + config.alias());
        }
        new SAMLSignatureProfileValidator().validate(signature);  // structural profile checks
        SignatureValidator.validate(signature, credential);       // cryptographic verification (throws if invalid)
    }

    private void verifyConditions(final Assertion assertion, final SamlProviderConfig config) {
        final Conditions conditions = assertion.getConditions();
        if (conditions == null) {
            throw new IllegalStateException("SAML assertion has no conditions for provider " + config.alias());
        }
        final long now = Instant.now().toEpochMilli();
        if (conditions.getNotBefore() != null && now + CLOCK_SKEW_MILLIS < conditions.getNotBefore().toEpochMilli()) {
            throw new IllegalStateException("SAML assertion not yet valid for provider " + config.alias());
        }
        if (conditions.getNotOnOrAfter() != null && now - CLOCK_SKEW_MILLIS >= conditions.getNotOnOrAfter().toEpochMilli()) {
            throw new IllegalStateException("SAML assertion expired for provider " + config.alias());
        }
        final boolean audienceOk = conditions.getAudienceRestrictions().stream()
                .map(AudienceRestriction::getAudiences)
                .flatMap(java.util.List::stream)
                .map(Audience::getURI)
                .anyMatch(uri -> config.spEntityId().equals(uri));
        if (!audienceOk) {
            throw new IllegalStateException("SAML assertion audience does not include " + config.spEntityId());
        }
    }

    /** One-time-use: reject an assertion ID already seen within its validity window. */
    private void verifyNotReplayed(final Assertion assertion, final SamlProviderConfig config) {
        final String assertionId = assertion.getID();
        if (assertionId == null || assertionId.isBlank()) {
            throw new IllegalStateException("SAML assertion has no ID (cannot replay-protect) for provider "
                    + config.alias());
        }
        final Conditions conditions = assertion.getConditions();
        final Instant expiresAt = conditions != null ? conditions.getNotOnOrAfter() : null;
        if (!replayCache.checkAndRecord(assertionId, expiresAt)) {
            throw new IllegalStateException("SAML assertion replay detected for provider " + config.alias());
        }
    }

    private Map<String, String> attributes(final Assertion assertion) {
        final Map<String, String> attributes = new LinkedHashMap<>();
        for (final AttributeStatement statement : assertion.getAttributeStatements()) {
            for (final Attribute attribute : statement.getAttributes()) {
                if (!attribute.getAttributeValues().isEmpty()) {
                    final Element dom = attribute.getAttributeValues().get(0).getDOM();
                    if (dom != null) {
                        attributes.put(attribute.getName(), dom.getTextContent());
                    }
                }
            }
        }
        return new HashMap<>(attributes);
    }

    private static X509Certificate parseCertificate(final String pem) throws Exception {
        final String base64 = pem.replace("-----BEGIN CERTIFICATE-----", "")
                .replace("-----END CERTIFICATE-----", "")
                .replaceAll("\\s", "");
        final byte[] der = Base64.getDecoder().decode(base64);
        return (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(der));
    }
}
