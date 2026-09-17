/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.eid;

import io.helixiam.common.net.OutboundUrlGuard;
import net.shibboleth.shared.xml.SerializeSupport;
import org.opensaml.core.config.InitializationService;
import org.opensaml.core.xml.XMLObjectBuilderFactory;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.Unmarshaller;
import org.opensaml.saml.common.SAMLObject;
import org.opensaml.saml.common.SAMLVersion;
import org.opensaml.saml.saml2.core.Artifact;
import org.opensaml.saml.saml2.core.ArtifactResolve;
import org.opensaml.saml.saml2.core.ArtifactResponse;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.core.StatusCode;
import org.opensaml.saml.security.impl.SAMLSignatureProfileValidator;
import org.opensaml.security.x509.BasicX509Credential;
import org.opensaml.xmlsec.signature.Signature;
import org.opensaml.xmlsec.signature.support.SignatureConstants;
import org.opensaml.xmlsec.signature.support.SignatureValidator;
import org.opensaml.xmlsec.signature.support.Signer;
import org.springframework.stereotype.Component;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.xml.namespace.QName;
import java.io.ByteArrayInputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.UUID;

/**
 * Helix IAM E6: production {@link EidArtifactResolver} for classic DigiD ("Koppelvlak SAML") — backed by
 * OpenSAML + the JDK HTTP client. Builds a signed {@code <samlp:ArtifactResolve>}, wraps it in a SOAP 1.1
 * envelope, and POSTs it to the IdP's Artifact Resolution Service (ARS) over TLS — using the SP signing
 * cert/key as the <b>mutual-TLS client identity</b> when present (DigiD requires PKIoverheid client auth on
 * the back-channel). It then verifies the {@code <samlp:ArtifactResponse>} signature against the IdP cert,
 * checks the status, and returns the embedded {@code <samlp:Response>} as base64 for the existing
 * {@link EidAssertionValidator} (so the inner assertion's signature / decryption / LoA checks are unchanged).
 */
@Component
public class OpenSamlEidArtifactResolver implements EidArtifactResolver {

    private static final String SOAP_NS = "http://schemas.xmlsoap.org/soap/envelope/";

    private final OutboundUrlGuard egressGuard;

    /** Secure default (block-private) for non-Spring construction. */
    public OpenSamlEidArtifactResolver() {
        this(new OutboundUrlGuard());
    }

    @org.springframework.beans.factory.annotation.Autowired
    public OpenSamlEidArtifactResolver(final OutboundUrlGuard egressGuard) {
        this.egressGuard = egressGuard;
    }

    static {
        try {
            InitializationService.initialize();
        } catch (final Exception e) {
            throw new IllegalStateException("Failed to initialize OpenSAML", e);
        }
    }

    @Override
    public String resolve(final EidProviderConfig config, final String samlArt) {
        if (config.artifactResolutionServiceUrl() == null || config.artifactResolutionServiceUrl().isBlank()) {
            throw new IllegalStateException("eID provider " + config.alias()
                    + " uses artifact binding but has no Artifact Resolution Service (ARS) URL");
        }
        egressGuard.checkAllowed(config.artifactResolutionServiceUrl()); // M6: ARS URL comes from admin eID config
        try {
            final String soap = soapEnvelope(signedArtifactResolve(config, samlArt));
            final String responseSoap = post(config, soap);
            final ArtifactResponse artifactResponse = parseArtifactResponse(responseSoap);
            verifyResponse(config, artifactResponse);

            final SAMLObject message = artifactResponse.getMessage();
            if (!(message instanceof Response response)) {
                throw new IllegalStateException("eID ArtifactResponse for provider " + config.alias()
                        + " did not contain a SAML Response");
            }
            final Element element = XMLObjectProviderRegistrySupport.getMarshallerFactory()
                    .getMarshaller(response).marshall(response);
            return Base64.getEncoder().encodeToString(
                    SerializeSupport.nodeToString(element).getBytes(StandardCharsets.UTF_8));
        } catch (final IllegalStateException e) {
            throw e;
        } catch (final Exception e) {
            throw new IllegalStateException("eID artifact resolution failed for provider " + config.alias()
                    + ": " + e.getMessage(), e);
        }
    }

    private ArtifactResolve signedArtifactResolve(final EidProviderConfig config, final String samlArt) throws Exception {
        final Issuer issuer = build(Issuer.DEFAULT_ELEMENT_NAME);
        issuer.setValue(config.spEntityId());

        final Artifact artifact = build(Artifact.DEFAULT_ELEMENT_NAME);
        artifact.setValue(samlArt);

        final ArtifactResolve resolve = build(ArtifactResolve.DEFAULT_ELEMENT_NAME);
        resolve.setID("_" + UUID.randomUUID());
        resolve.setVersion(SAMLVersion.VERSION_20);
        resolve.setIssueInstant(Instant.now());
        resolve.setDestination(config.artifactResolutionServiceUrl());
        resolve.setIssuer(issuer);
        resolve.setArtifact(artifact);

        final X509Certificate spCert = parseCertificate(config.spSigningCertificate());
        final PrivateKey spKey = parsePrivateKey(config.spSigningPrivateKey());
        final BasicX509Credential credential = new BasicX509Credential(spCert, spKey);
        final Signature signature = build(Signature.DEFAULT_ELEMENT_NAME);
        signature.setSigningCredential(credential);
        signature.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256);
        signature.setCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
        resolve.setSignature(signature);
        XMLObjectProviderRegistrySupport.getMarshallerFactory().getMarshaller(resolve).marshall(resolve);
        Signer.signObject(signature);
        return resolve;
    }

    private static String soapEnvelope(final ArtifactResolve resolve) throws Exception {
        final Element element = XMLObjectProviderRegistrySupport.getMarshallerFactory()
                .getMarshaller(resolve).marshall(resolve);
        final String inner = SerializeSupport.nodeToString(element).replaceFirst("<\\?xml[^>]*\\?>", "");
        return "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
                + "<soapenv:Envelope xmlns:soapenv=\"" + SOAP_NS + "\"><soapenv:Body>"
                + inner + "</soapenv:Body></soapenv:Envelope>";
    }

    private String post(final EidProviderConfig config, final String soap) throws Exception {
        final HttpClient client = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(10))
                .sslContext(clientSslContext(config))
                .build();
        final HttpRequest request = HttpRequest.newBuilder(URI.create(config.artifactResolutionServiceUrl()))
                .timeout(Duration.ofSeconds(15))
                .header("Content-Type", "text/xml; charset=utf-8")
                .header("SOAPAction", "http://www.oasis-open.org/committees/security")
                .POST(HttpRequest.BodyPublishers.ofString(soap, StandardCharsets.UTF_8))
                .build();
        final HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
        if (response.statusCode() / 100 != 2) {
            throw new IllegalStateException("eID ARS returned HTTP " + response.statusCode()
                    + " for provider " + config.alias());
        }
        return response.body();
    }

    /** Mutual-TLS: present the SP signing cert/key as the client identity (DigiD ARS requires it). */
    private static SSLContext clientSslContext(final EidProviderConfig config) throws Exception {
        final X509Certificate spCert = parseCertificate(config.spSigningCertificate());
        final PrivateKey spKey = parsePrivateKey(config.spSigningPrivateKey());
        if (spCert == null || spKey == null) {
            return SSLContext.getDefault(); // 1-way TLS — server trust via the system truststore
        }
        final KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(null, null);
        keyStore.setKeyEntry("sp", spKey, new char[0], new java.security.cert.Certificate[]{spCert});
        final KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(keyStore, new char[0]);
        final SSLContext context = SSLContext.getInstance("TLS");
        context.init(kmf.getKeyManagers(), null, null); // default trust managers verify the server cert chain
        return context;
    }

    private ArtifactResponse parseArtifactResponse(final String soap) throws Exception {
        final Element envelope = XMLObjectProviderRegistrySupport.getParserPool()
                .parse(new ByteArrayInputStream(soap.getBytes(StandardCharsets.UTF_8))).getDocumentElement();
        final Element body = firstChildElementNS(envelope, SOAP_NS, "Body");
        if (body == null) {
            throw new IllegalStateException("eID ARS response has no SOAP Body");
        }
        final Element artifactResponseEl = firstChildElement(body);
        if (artifactResponseEl == null || !"ArtifactResponse".equals(artifactResponseEl.getLocalName())) {
            throw new IllegalStateException("eID ARS response is not an ArtifactResponse (SOAP fault?)");
        }
        final Unmarshaller unmarshaller = XMLObjectProviderRegistrySupport.getUnmarshallerFactory()
                .getUnmarshaller(artifactResponseEl);
        return (ArtifactResponse) unmarshaller.unmarshall(artifactResponseEl);
    }

    /** Verify the ArtifactResponse signature (if present) against the IdP cert + require a success status. */
    private static void verifyResponse(final EidProviderConfig config, final ArtifactResponse artifactResponse)
            throws Exception {
        if (artifactResponse.getStatus() != null && artifactResponse.getStatus().getStatusCode() != null) {
            final String code = artifactResponse.getStatus().getStatusCode().getValue();
            if (code != null && !StatusCode.SUCCESS.equals(code)) {
                throw new IllegalStateException("eID ArtifactResponse status " + code
                        + " for provider " + config.alias());
            }
        }
        final Signature signature = artifactResponse.getSignature();
        if (signature != null) {
            final BasicX509Credential idpCredential = new BasicX509Credential(parseCertificate(config.idpSigningCertificate()));
            new SAMLSignatureProfileValidator().validate(signature);
            SignatureValidator.validate(signature, idpCredential);
        }
        // If the ArtifactResponse itself is unsigned, the embedded Response/Assertion signature is still
        // enforced downstream by EidAssertionValidator, so the resolved assertion is never trusted unsigned.
    }

    private static Element firstChildElementNS(final Element parent, final String ns, final String local) {
        for (Node n = parent.getFirstChild(); n != null; n = n.getNextSibling()) {
            if (n.getNodeType() == Node.ELEMENT_NODE && ns.equals(n.getNamespaceURI()) && local.equals(n.getLocalName())) {
                return (Element) n;
            }
        }
        return null;
    }

    private static Element firstChildElement(final Element parent) {
        for (Node n = parent.getFirstChild(); n != null; n = n.getNextSibling()) {
            if (n.getNodeType() == Node.ELEMENT_NODE) {
                return (Element) n;
            }
        }
        return null;
    }

    @SuppressWarnings("unchecked")
    private static <T> T build(final QName qname) {
        final XMLObjectBuilderFactory bf = XMLObjectProviderRegistrySupport.getBuilderFactory();
        return (T) bf.getBuilder(qname).buildObject(qname);
    }

    private static X509Certificate parseCertificate(final String pem) throws Exception {
        if (pem == null || pem.isBlank()) {
            return null;
        }
        final String base64 = pem.replace("-----BEGIN CERTIFICATE-----", "")
                .replace("-----END CERTIFICATE-----", "").replaceAll("\\s", "");
        return (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(Base64.getDecoder().decode(base64)));
    }

    private static PrivateKey parsePrivateKey(final String pem) throws Exception {
        if (pem == null || pem.isBlank()) {
            return null;
        }
        final String base64 = pem.replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "").replaceAll("\\s", "");
        return KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(Base64.getDecoder().decode(base64)));
    }
}
