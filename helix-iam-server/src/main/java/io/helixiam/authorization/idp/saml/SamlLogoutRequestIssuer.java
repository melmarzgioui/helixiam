/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.idp.saml;

import net.shibboleth.shared.xml.SerializeSupport;
import org.opensaml.core.config.InitializationService;
import org.opensaml.core.xml.XMLObjectBuilderFactory;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.core.LogoutRequest;
import org.opensaml.saml.saml2.core.NameID;
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
 * Helix IAM SSO P8: issues a signed SAML2 {@code <LogoutRequest>} — Helix (as IdP) propagating a Single
 * Logout to the OTHER SAML SPs in the user's session. Signed with the IdP key, addressed to the SP's SLO
 * endpoint, carrying the user's NameID so the SP can terminate the matching session.
 */
@Component
public class SamlLogoutRequestIssuer {

    static {
        try {
            InitializationService.initialize();
        } catch (final Exception e) {
            throw new IllegalStateException("Failed to initialize OpenSAML", e);
        }
    }

    public String issueLogoutRequest(final SamlIdpConfig idp, final String spSloUrl, final String nameId) {
        try {
            final LogoutRequest request = build(LogoutRequest.DEFAULT_ELEMENT_NAME);
            request.setID("_lq" + UUID.randomUUID());
            request.setIssueInstant(Instant.now());
            request.setDestination(spSloUrl);

            final Issuer issuer = build(Issuer.DEFAULT_ELEMENT_NAME);
            issuer.setValue(idp.idpEntityId());
            request.setIssuer(issuer);

            final NameID name = build(NameID.DEFAULT_ELEMENT_NAME);
            name.setValue(nameId);
            request.setNameID(name);

            sign(request, idp);
            final var dom = XMLObjectProviderRegistrySupport.getMarshallerFactory().getMarshaller(request).marshall(request);
            return Base64.getEncoder().encodeToString(SerializeSupport.nodeToString(dom).getBytes(StandardCharsets.UTF_8));
        } catch (final Exception e) {
            throw new IllegalStateException("Failed to issue SAML LogoutRequest for " + spSloUrl, e);
        }
    }

    private void sign(final LogoutRequest request, final SamlIdpConfig idp) throws Exception {
        final BasicX509Credential credential = new BasicX509Credential(
                parseCertificate(idp.signingCertificate()), parsePrivateKey(idp.signingPrivateKey()));
        final Signature signature = build(Signature.DEFAULT_ELEMENT_NAME);
        signature.setSigningCredential(credential);
        signature.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256);
        signature.setCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
        request.setSignature(signature);
        XMLObjectProviderRegistrySupport.getMarshallerFactory().getMarshaller(request).marshall(request);
        Signer.signObject(signature);
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
