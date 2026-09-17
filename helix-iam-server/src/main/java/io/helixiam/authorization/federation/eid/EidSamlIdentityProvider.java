/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.eid;

import io.helixiam.authorization.federation.spi.BrokeredIdentity;
import io.helixiam.authorization.federation.spi.IdentityProvider;
import io.helixiam.authorization.federation.spi.IdpMetadata;
import net.shibboleth.shared.xml.SerializeSupport;
import org.opensaml.core.config.InitializationService;
import org.opensaml.core.xml.XMLObjectBuilderFactory;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.saml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml.saml2.core.AuthnContextComparisonTypeEnumeration;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.core.RequestedAuthnContext;
import org.opensaml.security.x509.BasicX509Credential;
import org.opensaml.xmlsec.signature.Signature;
import org.opensaml.xmlsec.signature.support.SignatureConstants;
import org.opensaml.xmlsec.signature.support.Signer;

import javax.xml.namespace.QName;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Instant;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.function.Supplier;

/**
 * Helix IAM E6: the EU/NL eID connector on the federation {@link IdentityProvider} SPI — same registry
 * / broker / {@code /broker/{alias}} controller / session as the OIDC/SAML brokers.
 *
 * <ul>
 *   <li>{@code start} — builds an AuthnRequest carrying the minimum {@code RequestedAuthnContext}
 *       (level of assurance), <b>enveloped-XML-signs</b> it with the SP key, and returns it over the
 *       <b>HTTP-POST</b> binding (base64, no deflate) — the binding + signature DigiD/eHerkenning
 *       require.</li>
 *   <li>{@code callback} — verifies the RelayState (CSRF), validates the encrypted Response via
 *       {@link EidAssertionValidator} (decrypt {@code EncryptedID} + signature + LoA), and maps it to a
 *       {@link BrokeredIdentity}: the BSN / PersonIdentifier / entityConcernedID is the external
 *       subject, the LoA is the {@code loa} attribute, the identifier type the {@code subjectType}
 *       attribute. eID schemes assert no email, so the broker only JIT-provisions.</li>
 * </ul>
 */
public class EidSamlIdentityProvider implements IdentityProvider {

    static {
        try {
            InitializationService.initialize();
        } catch (final Exception e) {
            throw new IllegalStateException("Failed to initialize OpenSAML", e);
        }
    }

    /** Resolver used when none is supplied — fails only if the provider actually uses artifact binding. */
    private static final EidArtifactResolver UNCONFIGURED_RESOLVER = (cfg, art) -> {
        throw new IllegalStateException("eID provider " + cfg.alias()
                + " uses the SAML Artifact binding but no artifact resolver is configured");
    };

    private final EidProviderConfig config;
    private final EidAssertionValidator validator;
    private final EidArtifactResolver artifactResolver;
    private final io.helixiam.authorization.federation.UpstreamLogoutClient upstreamLogoutClient;
    private final Supplier<String> idGenerator;
    private final Supplier<Instant> instantSupplier;

    public EidSamlIdentityProvider(final EidProviderConfig config, final EidAssertionValidator validator) {
        this(config, validator, UNCONFIGURED_RESOLVER,
                new io.helixiam.authorization.federation.UpstreamLogoutClient.Http(), () -> "_" + UUID.randomUUID(), Instant::now);
    }

    public EidSamlIdentityProvider(final EidProviderConfig config, final EidAssertionValidator validator,
                                   final EidArtifactResolver artifactResolver) {
        this(config, validator, artifactResolver,
                new io.helixiam.authorization.federation.UpstreamLogoutClient.Http(), () -> "_" + UUID.randomUUID(), Instant::now);
    }

    EidSamlIdentityProvider(final EidProviderConfig config, final EidAssertionValidator validator,
                            final EidArtifactResolver artifactResolver,
                            final io.helixiam.authorization.federation.UpstreamLogoutClient upstreamLogoutClient,
                            final Supplier<String> idGenerator, final Supplier<Instant> instantSupplier) {
        this.config = config;
        this.validator = validator;
        this.artifactResolver = artifactResolver;
        this.upstreamLogoutClient = upstreamLogoutClient;
        this.idGenerator = idGenerator;
        this.instantSupplier = instantSupplier;
    }

    @Override
    public IdpMetadata metadata() {
        return IdpMetadata.of(config.alias(), IdpMetadata.Protocol.SAML2, config.displayName());
    }

    @Override
    public RedirectResponse start(final AuthnRequestContext context) {
        try {
            return config.authnRequestBinding() == EidProviderConfig.Binding.REDIRECT
                    ? startRedirect(context) : startPost(context);
        } catch (final Exception e) {
            throw new IllegalStateException("Failed to build the eID AuthnRequest for provider " + config.alias(), e);
        }
    }

    /** HTTP-POST binding (CombiConnect/eID-stelsel/eHerkenning/eIDAS): base64 of an enveloped-signed AuthnRequest. */
    private RedirectResponse startPost(final AuthnRequestContext context) throws Exception {
        final AuthnRequest authnRequest = buildAuthnRequest();
        signEnveloped(authnRequest);
        final String xml = SerializeSupport.nodeToString(
                XMLObjectProviderRegistrySupport.getMarshallerFactory().getMarshaller(authnRequest).marshall(authnRequest));
        final String samlRequest = Base64.getEncoder().encodeToString(xml.getBytes(StandardCharsets.UTF_8));
        return RedirectResponse.postForm(config.ssoUrl(),
                Map.of("SAMLRequest", samlRequest, "RelayState", context.state()));
    }

    /** HTTP-Redirect binding (classic DigiD SAML v3.x): DEFLATE+base64 request + detached query signature. */
    private RedirectResponse startRedirect(final AuthnRequestContext context) throws Exception {
        final AuthnRequest authnRequest = buildAuthnRequest(); // not enveloped-signed; the query is signed
        final String xml = SerializeSupport.nodeToString(
                XMLObjectProviderRegistrySupport.getMarshallerFactory().getMarshaller(authnRequest).marshall(authnRequest));
        final String samlRequest = enc(deflateBase64(xml));
        final String sigAlg = enc("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256");
        final String signingInput = "SAMLRequest=" + samlRequest + "&RelayState=" + enc(context.state()) + "&SigAlg=" + sigAlg;
        final String signature = enc(signQuery(signingInput));
        final String location = config.ssoUrl() + "?" + signingInput + "&Signature=" + signature;
        return new RedirectResponse(location, Map.of("RelayState", context.state()));
    }

    @Override
    public BrokeredIdentity callback(final CallbackContext context) {
        final Map<String, String> params = context.parameters();
        final String relayState = params.get("RelayState");
        if (context.expectedState() == null || !context.expectedState().equals(relayState)) {
            throw new IllegalStateException("eID RelayState mismatch (possible CSRF) for provider " + config.alias());
        }
        // Classic DigiD (Koppelvlak SAML) returns only a SAMLart on the front channel; resolve the signed
        // assertion over the SOAP back-channel. Modern eID POSTs the SAMLResponse straight to the ACS.
        // Either way the resolved base64 Response flows through the SAME validator (signature/decrypt/LoA).
        final String samlResponse;
        if (config.responseBinding() == EidProviderConfig.ResponseBinding.ARTIFACT) {
            final String artifact = params.get("SAMLart");
            if (artifact == null || artifact.isBlank()) {
                throw new IllegalArgumentException("eID artifact callback missing SAMLart for provider " + config.alias());
            }
            samlResponse = artifactResolver.resolve(config, artifact);
        } else {
            samlResponse = params.get("SAMLResponse");
            if (samlResponse == null || samlResponse.isBlank()) {
                throw new IllegalArgumentException("eID callback missing SAMLResponse for provider " + config.alias());
            }
        }

        final EidAssertion assertion = validator.validate(config, samlResponse, context.expectedState());

        final Map<String, String> attributes = new HashMap<>(assertion.attributes());
        if (assertion.authnContextClassRef() != null) {
            attributes.put("loa", assertion.authnContextClassRef());
        }
        if (assertion.subjectType() != null) {
            attributes.put("subjectType", assertion.subjectType()); // BSN / KvK / PersonIdentifier type
        }
        // Representation (DigiD Machtigen / eHerkenning): the subject is the REPRESENTED party; surface
        // the acting subject (the representative who authenticated) + the mandated service to the RP.
        if (assertion.representation() != null) {
            if (assertion.representation().actingSubjectId() != null) {
                attributes.put("actingSubject", assertion.representation().actingSubjectId());
            }
            if (assertion.representation().serviceId() != null) {
                attributes.put("serviceId", assertion.representation().serviceId());
            }
            attributes.put("representation", "true");
        }
        // eID schemes do not assert an email; emailVerified=false so the broker never links by email.
        return new BrokeredIdentity(config.alias(), assertion.subjectId(), null, false, attributes);
    }

    @Override
    public void logout(final LogoutContext context) {
        // SSO P9: SP-initiated federated logout to the eID broker's SLO endpoint — a signed LogoutRequest
        // over HTTP-Redirect (detached query signature with the SP key), delivered best-effort so a failure
        // never blocks the local Helix logout. No-op when no SLO endpoint is configured / no NameID captured.
        final String slo = config.singleLogoutServiceUrl();
        if (slo == null || slo.isBlank() || context.upstreamNameId() == null || context.upstreamNameId().isBlank()) {
            return;
        }
        try {
            final String sessionIndexXml = context.upstreamSessionIndex() == null || context.upstreamSessionIndex().isBlank()
                    ? "" : "<samlp:SessionIndex>" + xml(context.upstreamSessionIndex()) + "</samlp:SessionIndex>";
            final String logoutRequest = ""
                    + "<samlp:LogoutRequest xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\""
                    + " xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\""
                    + " ID=\"" + xml(idGenerator.get()) + "\" Version=\"2.0\""
                    + " IssueInstant=\"" + instantSupplier.get().toString() + "\""
                    + " Destination=\"" + xml(slo) + "\">"
                    + "<saml:Issuer>" + xml(config.spEntityId()) + "</saml:Issuer>"
                    + "<saml:NameID>" + xml(context.upstreamNameId()) + "</saml:NameID>"
                    + sessionIndexXml
                    + "</samlp:LogoutRequest>";
            final String samlRequest = enc(deflateBase64(logoutRequest));
            final String sigAlg = enc("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256");
            final String relayState = enc(context.realmId() == null ? "" : context.realmId());
            final String signingInput = "SAMLRequest=" + samlRequest + "&RelayState=" + relayState + "&SigAlg=" + sigAlg;
            final String signature = enc(signQuery(signingInput));
            upstreamLogoutClient.get(slo + (slo.contains("?") ? "&" : "?") + signingInput + "&Signature=" + signature);
        } catch (final RuntimeException e) {
            // upstream broker unreachable / rejected the logout — the local session is already gone.
        } catch (final Exception e) {
            // signing/encoding failure — never block the local logout.
        }
    }

    private static String xml(final String value) {
        return value == null ? "" : value.replace("&", "&amp;").replace("<", "&lt;")
                .replace(">", "&gt;").replace("\"", "&quot;");
    }

    private AuthnRequest buildAuthnRequest() {
        final Issuer issuer = build(Issuer.DEFAULT_ELEMENT_NAME);
        issuer.setValue(config.spEntityId());

        final AuthnRequest authnRequest = build(AuthnRequest.DEFAULT_ELEMENT_NAME);
        authnRequest.setID(idGenerator.get());
        authnRequest.setVersion(org.opensaml.saml.common.SAMLVersion.VERSION_20);
        authnRequest.setIssueInstant(instantSupplier.get());
        authnRequest.setDestination(config.ssoUrl());
        authnRequest.setAssertionConsumerServiceURL(config.assertionConsumerServiceUrl());
        // Ask the IdP to return the assertion the way this provider is configured to consume it:
        // HTTP-Artifact (classic DigiD → SAMLart + back-channel resolve) or HTTP-POST (modern eID).
        authnRequest.setProtocolBinding(config.responseBinding() == EidProviderConfig.ResponseBinding.ARTIFACT
                ? "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact"
                : "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST");
        authnRequest.setIssuer(issuer);

        if (config.minimumLoa() != null && !config.minimumLoa().isBlank()) {
            final AuthnContextClassRef classRef = build(AuthnContextClassRef.DEFAULT_ELEMENT_NAME);
            classRef.setURI(config.minimumLoa());
            final RequestedAuthnContext requested = build(RequestedAuthnContext.DEFAULT_ELEMENT_NAME);
            requested.setComparison(AuthnContextComparisonTypeEnumeration.MINIMUM);
            requested.getAuthnContextClassRefs().add(classRef);
            authnRequest.setRequestedAuthnContext(requested);
        }
        // A5: the eIDAS SAML profile requires the AuthnRequest to carry the eIDAS extensions
        // (SPType + the minimum-dataset RequestedAttributes). DigiD/eHerkenning must NOT get them.
        if (config.scheme() == EidScheme.EIDAS) {
            authnRequest.setExtensions(buildEidasExtensions());
        }
        return authnRequest;
    }

    // eIDAS SAML extensions namespace + attribute NameFormat.
    // eIDAS SAML spec: eIDAS SAML Attribute Profile v1.2 / eIDAS Message Format (eidas:SPType,
    // eidas:RequestedAttributes) — namespace http://eidas.europa.eu/saml-extensions.
    private static final String EIDAS_EXT_NS = "http://eidas.europa.eu/saml-extensions";
    private static final String EIDAS_EXT_PREFIX = "eidas";
    private static final String EIDAS_ATTR_NAME_FORMAT_URI = "urn:oasis:names:tc:SAML:2.0:attrname-format:uri";
    /** Default SPType when not driven from config. Public-sector SP is the safe default for a gov IAM. */
    private static final String DEFAULT_SP_TYPE = "public";
    private static final String EIDAS_NP = "http://eidas.europa.eu/attributes/naturalperson/";

    /**
     * The eIDAS natural-person minimum dataset (MDS). The four mandatory MDS attributes are requested as
     * required; the commonly-supported optional attributes are requested as not-required so an IdP that
     * can release them may, without failing when it cannot.
     * eIDAS SAML spec: eIDAS SAML Attribute Profile v1.2, section "Natural Person" (attribute URIs).
     */
    private static final java.util.List<EidasRequestedAttribute> EIDAS_MINIMUM_DATASET = java.util.List.of(
            new EidasRequestedAttribute(EIDAS_NP + "PersonIdentifier", true),
            new EidasRequestedAttribute(EIDAS_NP + "CurrentFamilyName", true),
            new EidasRequestedAttribute(EIDAS_NP + "CurrentGivenName", true),
            new EidasRequestedAttribute(EIDAS_NP + "DateOfBirth", true),
            new EidasRequestedAttribute(EIDAS_NP + "CurrentAddress", false),
            new EidasRequestedAttribute(EIDAS_NP + "PlaceOfBirth", false),
            new EidasRequestedAttribute(EIDAS_NP + "Gender", false));

    private record EidasRequestedAttribute(String name, boolean required) {
    }

    /** Builds {@code <samlp:Extensions>} with {@code <eidas:SPType>} + {@code <eidas:RequestedAttributes>}. */
    private org.opensaml.saml.saml2.core.Extensions buildEidasExtensions() {
        final org.opensaml.saml.saml2.core.Extensions extensions =
                build(org.opensaml.saml.saml2.core.Extensions.DEFAULT_ELEMENT_NAME);

        final org.opensaml.core.xml.schema.XSAny spType = eidasElement("SPType");
        spType.setTextContent(DEFAULT_SP_TYPE);
        extensions.getUnknownXMLObjects().add(spType);

        final org.opensaml.core.xml.schema.XSAny requestedAttributes = eidasElement("RequestedAttributes");
        for (final EidasRequestedAttribute attribute : EIDAS_MINIMUM_DATASET) {
            final org.opensaml.core.xml.schema.XSAny requestedAttribute = eidasElement("RequestedAttribute");
            requestedAttribute.getUnknownAttributes().put(new QName("Name"), attribute.name());
            requestedAttribute.getUnknownAttributes().put(new QName("NameFormat"), EIDAS_ATTR_NAME_FORMAT_URI);
            requestedAttribute.getUnknownAttributes().put(new QName("isRequired"), Boolean.toString(attribute.required()));
            requestedAttributes.getUnknownXMLObjects().add(requestedAttribute);
        }
        extensions.getUnknownXMLObjects().add(requestedAttributes);
        return extensions;
    }

    /** An {@code eidas:}-namespaced element built as an OpenSAML {@link org.opensaml.core.xml.schema.XSAny}. */
    @SuppressWarnings("unchecked")
    private static org.opensaml.core.xml.schema.XSAny eidasElement(final String localName) {
        final org.opensaml.core.xml.XMLObjectBuilder<org.opensaml.core.xml.schema.XSAny> builder =
                (org.opensaml.core.xml.XMLObjectBuilder<org.opensaml.core.xml.schema.XSAny>)
                        XMLObjectProviderRegistrySupport.getBuilderFactory()
                                .getBuilder(org.opensaml.core.xml.schema.XSAny.TYPE_NAME);
        return builder.buildObject(EIDAS_EXT_NS, localName, EIDAS_EXT_PREFIX);
    }

    /** RSA-SHA256 signature over the HTTP-Redirect query string (detached signature). */
    private String signQuery(final String signingInput) throws Exception {
        final java.security.Signature signer = java.security.Signature.getInstance("SHA256withRSA");
        signer.initSign(parsePrivateKey(config.spSigningPrivateKey()));
        signer.update(signingInput.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(signer.sign());
    }

    /** DEFLATE (raw, no zlib header) + base64 — the SAML HTTP-Redirect binding encoding. */
    private static String deflateBase64(final String xml) throws Exception {
        final java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
        final java.util.zip.Deflater deflater = new java.util.zip.Deflater(java.util.zip.Deflater.DEFAULT_COMPRESSION, true);
        try (java.util.zip.DeflaterOutputStream dos = new java.util.zip.DeflaterOutputStream(out, deflater)) {
            dos.write(xml.getBytes(StandardCharsets.UTF_8));
        } finally {
            deflater.end();
        }
        return Base64.getEncoder().encodeToString(out.toByteArray());
    }

    private static String enc(final String value) {
        return java.net.URLEncoder.encode(value, StandardCharsets.UTF_8);
    }

    private void signEnveloped(final AuthnRequest authnRequest) throws Exception {
        final X509Certificate spCert = parseCertificate(config.spSigningCertificate());
        final PrivateKey spKey = parsePrivateKey(config.spSigningPrivateKey());
        final BasicX509Credential credential = new BasicX509Credential(spCert, spKey);

        final Signature signature = build(Signature.DEFAULT_ELEMENT_NAME);
        signature.setSigningCredential(credential);
        signature.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256);
        signature.setCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
        authnRequest.setSignature(signature);

        XMLObjectProviderRegistrySupport.getMarshallerFactory().getMarshaller(authnRequest).marshall(authnRequest);
        Signer.signObject(signature);
    }

    @SuppressWarnings("unchecked")
    private static <T> T build(final QName qname) {
        final XMLObjectBuilderFactory bf = XMLObjectProviderRegistrySupport.getBuilderFactory();
        return (T) bf.getBuilder(qname).buildObject(qname);
    }

    private static X509Certificate parseCertificate(final String pem) throws Exception {
        if (pem == null || pem.isBlank()) {
            throw new IllegalStateException("eID provider requires an SP signing certificate");
        }
        final String base64 = pem.replace("-----BEGIN CERTIFICATE-----", "")
                .replace("-----END CERTIFICATE-----", "").replaceAll("\\s", "");
        return (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(new java.io.ByteArrayInputStream(Base64.getDecoder().decode(base64)));
    }

    private static PrivateKey parsePrivateKey(final String pem) throws Exception {
        if (pem == null || pem.isBlank()) {
            throw new IllegalStateException("eID provider requires an SP signing private key");
        }
        final String base64 = pem.replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "").replaceAll("\\s", "");
        return KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(Base64.getDecoder().decode(base64)));
    }
}
