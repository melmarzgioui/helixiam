package io.helixiam.authorization.idp.saml;

import net.shibboleth.utilities.java.support.xml.ParserPool;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensaml.core.config.InitializationService;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.Unmarshaller;
import org.opensaml.saml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.security.impl.SAMLSignatureProfileValidator;
import org.opensaml.security.x509.BasicX509Credential;
import org.opensaml.xmlsec.signature.Signature;
import org.opensaml.xmlsec.signature.support.SignatureValidator;
import org.springframework.stereotype.Component;
import org.w3c.dom.Element;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.zip.Inflater;
import java.util.zip.InflaterInputStream;

/**
 * Helix IAM E7.1 + WSO2-class: parses an inbound SP {@code SAMLRequest} (AuthnRequest) on either the
 * HTTP-POST binding (base64) or the HTTP-Redirect binding (raw-DEFLATE + base64), and — when the SP is
 * configured with {@code wantAuthnRequestsSigned} — verifies the SP's signature (embedded XML signature for
 * POST; the query-string signature per the SAML Redirect binding for GET).
 */
@Component
public class SamlAuthnRequestParser {

    private static final Logger LOG = LogManager.getLogger(SamlAuthnRequestParser.class);

    static {
        try {
            InitializationService.initialize();
        } catch (final Exception e) {
            throw new IllegalStateException("Failed to initialize OpenSAML", e);
        }
    }

    /** The fields Helix needs from the SP's AuthnRequest (incl. WSO2-class protocol controls). */
    public record AuthnRequestInfo(String spEntityId, String requestId, String assertionConsumerServiceUrl,
                                   Integer assertionConsumerServiceIndex, boolean forceAuthn, boolean isPassive,
                                   String requestedAuthnContextClassRef, String nameIdPolicyFormat) {
    }

    public AuthnRequestInfo parse(final String samlRequest, final boolean redirectBinding) {
        try {
            final AuthnRequest r = unmarshal(samlRequest, redirectBinding);
            final String spEntityId = r.getIssuer() == null ? null : r.getIssuer().getValue();
            final String reqCtx = r.getRequestedAuthnContext() == null
                    || r.getRequestedAuthnContext().getAuthnContextClassRefs().isEmpty() ? null
                    : r.getRequestedAuthnContext().getAuthnContextClassRefs().stream()
                        .map(AuthnContextClassRef::getURI).findFirst().orElse(null);
            final String nameIdFmt = r.getNameIDPolicy() == null ? null : r.getNameIDPolicy().getFormat();
            return new AuthnRequestInfo(spEntityId, r.getID(), r.getAssertionConsumerServiceURL(),
                    r.getAssertionConsumerServiceIndex(),
                    r.isForceAuthn() != null && r.isForceAuthn(),
                    r.isPassive() != null && r.isPassive(),
                    reqCtx, nameIdFmt);
        } catch (final Exception e) {
            throw new IllegalStateException("Invalid SAML AuthnRequest: " + e.getMessage(), e);
        }
    }

    /** True when the POST-binding AuthnRequest carries a valid embedded XML signature made by {@code certPem}. */
    public boolean isPostSignatureValid(final String samlRequest, final String certPem) {
        if (certPem == null || certPem.isBlank()) {
            return false;
        }
        try {
            final Signature signature = unmarshal(samlRequest, false).getSignature();
            if (signature == null) {
                return false;
            }
            new SAMLSignatureProfileValidator().validate(signature);
            SignatureValidator.validate(signature, new BasicX509Credential(parseCertificate(certPem)));
            return true;
        } catch (final Exception e) {
            LOG.debug("SAML AuthnRequest POST signature validation failed: {}", e.getMessage());
            return false;
        }
    }

    /**
     * True when the HTTP-Redirect binding signature verifies. Per the SAML binding, the signed octet string
     * is {@code SAMLRequest=<v>&RelayState=<v>&SigAlg=<v>} using the RAW (still URL-encoded) values in that
     * order (RelayState omitted if absent); {@code Signature} is the base64 signature over it.
     */
    public boolean isRedirectSignatureValid(final String rawQueryString, final String certPem) {
        if (certPem == null || certPem.isBlank() || rawQueryString == null) {
            return false;
        }
        try {
            final String samlRequest = rawParam(rawQueryString, "SAMLRequest");
            final String relayState = rawParam(rawQueryString, "RelayState");
            final String sigAlg = rawParam(rawQueryString, "SigAlg");
            final String signatureB64 = rawParam(rawQueryString, "Signature");
            if (samlRequest == null || sigAlg == null || signatureB64 == null) {
                return false;
            }
            final StringBuilder signed = new StringBuilder("SAMLRequest=").append(samlRequest);
            if (relayState != null) {
                signed.append("&RelayState=").append(relayState);
            }
            signed.append("&SigAlg=").append(sigAlg);

            final String sigAlgUri = java.net.URLDecoder.decode(sigAlg, java.nio.charset.StandardCharsets.UTF_8);
            final java.security.Signature verifier = java.security.Signature.getInstance(jca(sigAlgUri));
            final PublicKey publicKey = parseCertificate(certPem).getPublicKey();
            verifier.initVerify(publicKey);
            verifier.update(signed.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8));
            final byte[] sig = Base64.getDecoder().decode(
                    java.net.URLDecoder.decode(signatureB64, java.nio.charset.StandardCharsets.UTF_8));
            return verifier.verify(sig);
        } catch (final Exception e) {
            LOG.debug("SAML AuthnRequest redirect signature validation failed: {}", e.getMessage());
            return false;
        }
    }

    /** Pull a parameter's raw (still percent-encoded) value out of the raw query string. */
    private static String rawParam(final String rawQueryString, final String name) {
        for (final String pair : rawQueryString.split("&")) {
            final int eq = pair.indexOf('=');
            if (eq > 0 && pair.substring(0, eq).equals(name)) {
                return pair.substring(eq + 1);
            }
        }
        return null;
    }

    private static String jca(final String sigAlgUri) {
        if (sigAlgUri.endsWith("rsa-sha1")) {
            return "SHA1withRSA";
        }
        if (sigAlgUri.endsWith("rsa-sha512")) {
            return "SHA512withRSA";
        }
        return "SHA256withRSA";
    }

    private static AuthnRequest unmarshal(final String samlRequest, final boolean redirectBinding) {
        try {
            final byte[] decoded = Base64.getMimeDecoder().decode(samlRequest);
            final byte[] xml = redirectBinding ? inflate(decoded) : decoded;
            final ParserPool parserPool = XMLObjectProviderRegistrySupport.getParserPool();
            final Element element = parserPool.parse(new ByteArrayInputStream(xml)).getDocumentElement();
            final Unmarshaller unmarshaller = XMLObjectProviderRegistrySupport.getUnmarshallerFactory()
                    .getUnmarshaller(element);
            return (AuthnRequest) unmarshaller.unmarshall(element);
        } catch (final Exception e) {
            throw new IllegalStateException("Invalid SAML AuthnRequest: " + e.getMessage(), e);
        }
    }

    private static X509Certificate parseCertificate(final String pem) throws Exception {
        final String base64 = pem.replace("-----BEGIN CERTIFICATE-----", "")
                .replace("-----END CERTIFICATE-----", "").replaceAll("\\s", "");
        return (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(Base64.getDecoder().decode(base64)));
    }

    private static byte[] inflate(final byte[] deflated) throws Exception {
        final ByteArrayOutputStream out = new ByteArrayOutputStream();
        try (InflaterInputStream iis = new InflaterInputStream(new ByteArrayInputStream(deflated), new Inflater(true))) {
            iis.transferTo(out);
        }
        return out.toByteArray();
    }
}
