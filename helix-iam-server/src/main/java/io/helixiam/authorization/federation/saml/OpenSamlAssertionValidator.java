/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.saml;

import net.shibboleth.shared.xml.ParserPool;
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
import org.opensaml.saml.saml2.core.Status;
import org.opensaml.saml.saml2.core.StatusCode;
import org.opensaml.saml.saml2.core.SubjectConfirmation;
import org.opensaml.saml.saml2.core.SubjectConfirmationData;
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

            // SAML-3 (S-M3): the Response must signal success before any assertion is consumed. A
            // failed-auth Response that still carries an assertion must not log the user in.
            verifyStatusSuccess(response, config);

            if (response.getIssuer() == null || !config.idpEntityId().equals(response.getIssuer().getValue())) {
                throw new IllegalStateException("SAML response issuer mismatch for provider " + config.alias());
            }
            if (response.getAssertions().isEmpty()) {
                throw new IllegalStateException("SAML response has no assertion for provider " + config.alias());
            }
            final Assertion assertion = response.getAssertions().get(0);

            // SAML-2 (S-H2): the assertion's OWN Issuer must match the configured IdP entityId — defense
            // in depth over the signature check (mirrors OpenSamlEidAssertionValidator). Guards against a
            // shared/cross-issuer signing key or an IdP misissuing an assertion for another entity.
            if (assertion.getIssuer() == null || !config.idpEntityId().equals(assertion.getIssuer().getValue())) {
                throw new IllegalStateException("SAML assertion issuer mismatch for provider " + config.alias());
            }

            verifySignature(response, assertion, config);
            verifyConditions(assertion, config);
            verifySubjectConfirmation(assertion, config);
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

    /** Reject unless the Response status is {@code urn:oasis:names:tc:SAML:2.0:status:Success}. */
    private void verifyStatusSuccess(final Response response, final SamlProviderConfig config) {
        final Status status = response.getStatus();
        final StatusCode code = status != null ? status.getStatusCode() : null;
        if (code == null || !StatusCode.SUCCESS.equals(code.getValue())) {
            throw new IllegalStateException("SAML response status is not Success for provider " + config.alias());
        }
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
        // SAML-1 (S-H1): the assertion MUST carry an enforceable expiry. A missing Conditions/NotOnOrAfter
        // previously left the assertion with no expiry AND no replay protection (infinitely replayable).
        if (conditions.getNotOnOrAfter() == null) {
            throw new IllegalStateException("SAML assertion has no Conditions/NotOnOrAfter (no enforceable expiry) "
                    + "for provider " + config.alias());
        }
        if (now - CLOCK_SKEW_MILLIS >= conditions.getNotOnOrAfter().toEpochMilli()) {
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

    /**
     * SAML-1 (S-H1): bind the bearer assertion to this SP. The SAML 2.0 Web Browser SSO profile
     * requires a {@code SubjectConfirmation[@Method=bearer]} whose {@code SubjectConfirmationData}
     * has a {@code Recipient} equal to our ACS and a {@code NotOnOrAfter} in the future; without this,
     * a stolen/misdelivered bearer assertion is not tied to the in-flight login.
     *
     * <p><b>InResponseTo:</b> if present it MUST match the AuthnRequest id this SP issued (SP-initiated);
     * if absent the assertion is unsolicited (IdP-initiated SSO), which is legitimate. We therefore do
     * NOT unconditionally require InResponseTo — that would break IdP-initiated SSO. The broker does not
     * yet track outbound AuthnRequest ids ({@code Saml2IdentityProvider.start} mints an id but never
     * stashes it; the RelayState carries the realm anti-forgery state, not the request id), so the
     * InResponseTo↔request-id binding is a documented TODO below. Recipient + NotOnOrAfter are enforced
     * now for both solicited and unsolicited assertions.
     */
    private void verifySubjectConfirmation(final Assertion assertion, final SamlProviderConfig config) {
        if (assertion.getSubject() == null) {
            throw new IllegalStateException("SAML assertion has no subject for provider " + config.alias());
        }
        final long now = Instant.now().toEpochMilli();
        for (final SubjectConfirmation confirmation : assertion.getSubject().getSubjectConfirmations()) {
            if (!SubjectConfirmation.METHOD_BEARER.equals(confirmation.getMethod())) {
                continue;
            }
            final SubjectConfirmationData data = confirmation.getSubjectConfirmationData();
            if (data == null) {
                continue;
            }
            // Recipient MUST equal this SP's ACS/callback URL for the realm.
            if (data.getRecipient() == null || !config.assertionConsumerServiceUrl().equals(data.getRecipient())) {
                continue;
            }
            // Bearer NotOnOrAfter MUST be present and in the future (with skew).
            if (data.getNotOnOrAfter() == null || now - CLOCK_SKEW_MILLIS >= data.getNotOnOrAfter().toEpochMilli()) {
                continue;
            }
            // NotBefore is not permitted for bearer per profile, but enforce it if the IdP set it.
            if (data.getNotBefore() != null && now + CLOCK_SKEW_MILLIS < data.getNotBefore().toEpochMilli()) {
                continue;
            }
            // TODO(SAML-1/S-H1): when data.getInResponseTo() is non-null, bind it to the AuthnRequest id
            // this SP issued for the session (requires the broker to persist outbound request ids, e.g.
            // via RelayState or a request cache). Absent InResponseTo = unsolicited/IdP-initiated SSO and
            // remains valid, so this binding must stay conditional on presence to avoid breaking that flow.
            return; // a spec-valid bearer SubjectConfirmation addressed to us
        }
        throw new IllegalStateException("SAML assertion has no valid bearer SubjectConfirmation "
                + "(Recipient must equal " + config.assertionConsumerServiceUrl()
                + " with a future NotOnOrAfter) for provider " + config.alias());
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
