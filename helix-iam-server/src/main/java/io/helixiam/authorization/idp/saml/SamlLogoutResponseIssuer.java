package io.helixiam.authorization.idp.saml;

import net.shibboleth.utilities.java.support.xml.SerializeSupport;
import org.opensaml.core.config.InitializationService;
import org.opensaml.core.xml.XMLObjectBuilderFactory;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.core.LogoutResponse;
import org.opensaml.saml.saml2.core.Status;
import org.opensaml.saml.saml2.core.StatusCode;
import org.opensaml.security.x509.BasicX509Credential;
import org.opensaml.xmlsec.signature.Signature;
import org.opensaml.xmlsec.signature.support.SignatureConstants;
import org.opensaml.xmlsec.signature.support.Signer;
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
import java.util.Base64;
import java.util.UUID;

/**
 * Helix IAM E7.2: issues a signed SAML2 {@code <LogoutResponse>} for Single Logout — Helix (as IdP)
 * confirming an SP's LogoutRequest. Signed with the IdP key, Status=Success, addressed to the SP's
 * SLO service, echoing the request id.
 */
@Component
public class SamlLogoutResponseIssuer {

    static {
        try {
            InitializationService.initialize();
        } catch (final Exception e) {
            throw new IllegalStateException("Failed to initialize OpenSAML", e);
        }
    }

    public String issueLogoutResponse(final SamlIdpConfig idp, final String spSloUrl, final String inResponseTo) {
        try {
            final LogoutResponse response = build(LogoutResponse.DEFAULT_ELEMENT_NAME);
            response.setID("_lr" + UUID.randomUUID());
            response.setIssueInstant(Instant.now());
            response.setDestination(spSloUrl);
            if (inResponseTo != null && !inResponseTo.isBlank()) {
                response.setInResponseTo(inResponseTo);
            }
            final Issuer issuer = build(Issuer.DEFAULT_ELEMENT_NAME);
            issuer.setValue(idp.idpEntityId());
            response.setIssuer(issuer);
            response.setStatus(successStatus());

            sign(response, idp);
            final var dom = XMLObjectProviderRegistrySupport.getMarshallerFactory().getMarshaller(response).marshall(response);
            return Base64.getEncoder().encodeToString(SerializeSupport.nodeToString(dom).getBytes(StandardCharsets.UTF_8));
        } catch (final Exception e) {
            throw new IllegalStateException("Failed to issue SAML LogoutResponse for " + spSloUrl, e);
        }
    }

    private void sign(final LogoutResponse response, final SamlIdpConfig idp) throws Exception {
        final BasicX509Credential credential = new BasicX509Credential(
                parseCertificate(idp.signingCertificate()), parsePrivateKey(idp.signingPrivateKey()));
        final Signature signature = build(Signature.DEFAULT_ELEMENT_NAME);
        signature.setSigningCredential(credential);
        signature.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256);
        signature.setCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
        response.setSignature(signature);
        XMLObjectProviderRegistrySupport.getMarshallerFactory().getMarshaller(response).marshall(response);
        Signer.signObject(signature);
    }

    private static Status successStatus() {
        final StatusCode code = build(StatusCode.DEFAULT_ELEMENT_NAME);
        code.setValue(StatusCode.SUCCESS);
        final Status status = build(Status.DEFAULT_ELEMENT_NAME);
        status.setStatusCode(code);
        return status;
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
