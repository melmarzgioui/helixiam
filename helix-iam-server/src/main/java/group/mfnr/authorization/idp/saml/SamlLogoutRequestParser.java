package group.mfnr.authorization.idp.saml;

import net.shibboleth.utilities.java.support.xml.ParserPool;
import org.opensaml.core.config.InitializationService;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.Unmarshaller;
import org.opensaml.saml.saml2.core.LogoutRequest;
import org.opensaml.saml.security.impl.SAMLSignatureProfileValidator;
import org.opensaml.security.x509.BasicX509Credential;
import org.opensaml.xmlsec.signature.Signature;
import org.opensaml.xmlsec.signature.support.SignatureValidator;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.stereotype.Component;
import org.w3c.dom.Element;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.zip.Inflater;
import java.util.zip.InflaterInputStream;

/**
 * Helix IAM SSO P8: parses an inbound SP {@code <LogoutRequest>} (HTTP-POST base64, or HTTP-Redirect
 * raw-DEFLATE+base64) into the requesting SP's entity id, request id and the subject NameID, and validates
 * its embedded XML signature against the SP's registered signing certificate.
 */
@Component
public class SamlLogoutRequestParser {

    private static final Logger LOG = LogManager.getLogger(SamlLogoutRequestParser.class);

    static {
        try {
            InitializationService.initialize();
        } catch (final Exception e) {
            throw new IllegalStateException("Failed to initialize OpenSAML", e);
        }
    }

    /** The fields Helix needs from the SP's LogoutRequest. */
    public record LogoutRequestInfo(String spEntityId, String requestId, String nameId) {
    }

    public LogoutRequestInfo parse(final String samlRequest, final boolean redirectBinding) {
        final LogoutRequest logoutRequest = unmarshal(samlRequest, redirectBinding);
        final String spEntityId = logoutRequest.getIssuer() == null ? null : logoutRequest.getIssuer().getValue();
        final String nameId = logoutRequest.getNameID() == null ? null : logoutRequest.getNameID().getValue();
        return new LogoutRequestInfo(spEntityId, logoutRequest.getID(), nameId);
    }

    /**
     * True only when the LogoutRequest carries a valid XML signature made by the key matching
     * {@code certPem}. A request with no signature, or no configured cert, or a mismatching key, is false.
     */
    public boolean isSignatureValid(final String samlRequest, final boolean redirectBinding, final String certPem) {
        if (certPem == null || certPem.isBlank()) {
            return false;
        }
        try {
            final LogoutRequest logoutRequest = unmarshal(samlRequest, redirectBinding);
            final Signature signature = logoutRequest.getSignature();
            if (signature == null) {
                return false;
            }
            new SAMLSignatureProfileValidator().validate(signature);
            SignatureValidator.validate(signature, new BasicX509Credential(parseCertificate(certPem)));
            return true;
        } catch (final Exception e) {
            LOG.debug("SAML LogoutRequest signature validation failed: {}", e.getMessage());
            return false;
        }
    }

    private static LogoutRequest unmarshal(final String samlRequest, final boolean redirectBinding) {
        try {
            final byte[] decoded = Base64.getMimeDecoder().decode(samlRequest);
            final byte[] xml = redirectBinding ? inflate(decoded) : decoded;
            final ParserPool parserPool = XMLObjectProviderRegistrySupport.getParserPool();
            final Element element = parserPool.parse(new ByteArrayInputStream(xml)).getDocumentElement();
            final Unmarshaller unmarshaller = XMLObjectProviderRegistrySupport.getUnmarshallerFactory()
                    .getUnmarshaller(element);
            return (LogoutRequest) unmarshaller.unmarshall(element);
        } catch (final Exception e) {
            throw new IllegalStateException("Invalid SAML LogoutRequest: " + e.getMessage(), e);
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
