/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.eid;

import com.sun.net.httpserver.HttpServer;
import io.helixiam.common.net.OutboundUrlGuard;
import net.shibboleth.shared.xml.SerializeSupport;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.opensaml.core.config.InitializationService;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.saml.common.SAMLVersion;
import org.opensaml.saml.saml2.core.ArtifactResponse;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.core.Status;
import org.opensaml.saml.saml2.core.StatusCode;
import org.opensaml.security.x509.BasicX509Credential;
import org.opensaml.xmlsec.signature.Signature;
import org.opensaml.xmlsec.signature.support.SignatureConstants;
import org.opensaml.xmlsec.signature.support.Signer;

import javax.xml.namespace.QName;
import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * DEEP-3: the eID {@code ArtifactResponse} envelope returned over the SOAP back-channel must be signed by the
 * IdP's metadata signing key. An unsigned envelope is refused when the IdP has a signing key, and any
 * envelope is refused when the IdP's metadata gives no signing key at all. Runs against a loopback ARS stub.
 */
class OpenSamlEidArtifactResolverTest {

    private static final String IDP_ENTITY = "https://digid.example/entity";
    private static final String SP_ENTITY = "https://helix.test/sp";

    private static KeyPair idpKey;
    private static X509Certificate idpCert;
    private static String idpCertPem;
    private static KeyPair otherKey;
    private static X509Certificate otherCert;
    private static String spKeyPem;
    private static String spCertPem;

    private HttpServer ars;
    private final AtomicReference<String> arsReply = new AtomicReference<>();
    private String arsUrl;
    private final OpenSamlEidArtifactResolver resolver = new OpenSamlEidArtifactResolver(new OutboundUrlGuard(true));

    @BeforeAll
    static void init() throws Exception {
        InitializationService.initialize();
        idpKey = rsa();
        idpCert = selfSigned(idpKey, "CN=DigiD");
        idpCertPem = pem(idpCert);
        otherKey = rsa();
        otherCert = selfSigned(otherKey, "CN=Attacker");
        final KeyPair spKey = rsa();
        spCertPem = pem(selfSigned(spKey, "CN=HelixSP"));
        spKeyPem = "-----BEGIN PRIVATE KEY-----\n"
                + Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(spKey.getPrivate().getEncoded())
                + "\n-----END PRIVATE KEY-----\n";
    }

    @BeforeEach
    void startArs() throws Exception {
        ars = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        ars.createContext("/ars", exchange -> {
            exchange.getRequestBody().readAllBytes();
            final byte[] body = arsReply.get().getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", "text/xml; charset=utf-8");
            exchange.sendResponseHeaders(200, body.length);
            exchange.getResponseBody().write(body);
            exchange.close();
        });
        ars.start();
        arsUrl = "http://127.0.0.1:" + ars.getAddress().getPort() + "/ars";
    }

    @AfterEach
    void stopArs() {
        ars.stop(0);
    }

    @Test
    void acceptsAnArtifactResponseSignedByTheIdpMetadataKey() throws Exception {
        arsReply.set(soap(artifactResponse(idpKey, idpCert)));

        final String resolved = resolver.resolve(config(idpCertPem), "art-1");

        final String xml = new String(Base64.getDecoder().decode(resolved), StandardCharsets.UTF_8);
        assertThat(xml).contains("Response").contains(IDP_ENTITY);
    }

    @Test
    void rejectsAnUnsignedArtifactResponseWhenTheIdpMetadataHasASigningKey() throws Exception {
        arsReply.set(soap(artifactResponse(null, null)));

        assertThatThrownBy(() -> resolver.resolve(config(idpCertPem), "art-2"))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("not signed");
    }

    @Test
    void rejectsAnArtifactResponseSignedByAnotherKey() throws Exception {
        arsReply.set(soap(artifactResponse(otherKey, otherCert)));

        assertThatThrownBy(() -> resolver.resolve(config(idpCertPem), "art-3"))
                .isInstanceOf(IllegalStateException.class);
    }

    @Test
    void refusesAnUnsignedArtifactResponseWhenTheIdpMetadataGivesNoSigningKey() throws Exception {
        arsReply.set(soap(artifactResponse(null, null)));

        assertThatThrownBy(() -> resolver.resolve(config(null), "art-4"))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("no IdP signing certificate");
    }

    @Test
    void refusesASignedArtifactResponseWhenTheIdpMetadataGivesNoSigningKey() throws Exception {
        arsReply.set(soap(artifactResponse(idpKey, idpCert)));

        assertThatThrownBy(() -> resolver.resolve(config(null), "art-5"))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("no IdP signing certificate");
    }

    // --- helpers -------------------------------------------------------------------------------

    private EidProviderConfig config(final String idpSigningCertPem) {
        return new EidProviderConfig(EidScheme.DIGID, "digid", "DigiD", "https://digid.example/sso",
                IDP_ENTITY, SP_ENTITY, "https://helix.test/acs", idpSigningCertPem, null,
                spKeyPem, spCertPem, null, null, EidProviderConfig.Binding.POST, null,
                EidProviderConfig.ResponseBinding.ARTIFACT, arsUrl);
    }

    /** An ArtifactResponse carrying an (unsigned) Response; the envelope is signed when a key is given. */
    private static ArtifactResponse artifactResponse(final KeyPair signingKey, final X509Certificate signingCert)
            throws Exception {
        final Issuer responseIssuer = build(Issuer.DEFAULT_ELEMENT_NAME);
        responseIssuer.setValue(IDP_ENTITY);
        final Response response = build(Response.DEFAULT_ELEMENT_NAME);
        response.setID("_r" + System.nanoTime());
        response.setVersion(SAMLVersion.VERSION_20);
        response.setIssueInstant(Instant.now());
        response.setIssuer(responseIssuer);
        response.setStatus(success());

        final Issuer issuer = build(Issuer.DEFAULT_ELEMENT_NAME);
        issuer.setValue(IDP_ENTITY);
        final ArtifactResponse artifactResponse = build(ArtifactResponse.DEFAULT_ELEMENT_NAME);
        artifactResponse.setID("_ar" + System.nanoTime());
        artifactResponse.setVersion(SAMLVersion.VERSION_20);
        artifactResponse.setIssueInstant(Instant.now());
        artifactResponse.setIssuer(issuer);
        artifactResponse.setStatus(success());
        artifactResponse.setMessage(response);

        if (signingKey != null) {
            final Signature signature = build(Signature.DEFAULT_ELEMENT_NAME);
            signature.setSigningCredential(new BasicX509Credential(signingCert, signingKey.getPrivate()));
            signature.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256);
            signature.setCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
            artifactResponse.setSignature(signature);
            XMLObjectProviderRegistrySupport.getMarshallerFactory().getMarshaller(artifactResponse)
                    .marshall(artifactResponse);
            Signer.signObject(signature);
        } else {
            XMLObjectProviderRegistrySupport.getMarshallerFactory().getMarshaller(artifactResponse)
                    .marshall(artifactResponse);
        }
        return artifactResponse;
    }

    private static String soap(final ArtifactResponse artifactResponse) {
        final String inner = SerializeSupport.nodeToString(artifactResponse.getDOM())
                .replaceFirst("<\\?xml[^>]*\\?>", "");
        return "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
                + "<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\"><soapenv:Body>"
                + inner + "</soapenv:Body></soapenv:Envelope>";
    }

    private static Status success() {
        final StatusCode code = build(StatusCode.DEFAULT_ELEMENT_NAME);
        code.setValue(StatusCode.SUCCESS);
        final Status status = build(Status.DEFAULT_ELEMENT_NAME);
        status.setStatusCode(code);
        return status;
    }

    @SuppressWarnings("unchecked")
    private static <T> T build(final QName qname) {
        return (T) XMLObjectProviderRegistrySupport.getBuilderFactory().getBuilder(qname).buildObject(qname);
    }

    private static KeyPair rsa() throws Exception {
        final KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        return kpg.generateKeyPair();
    }

    private static X509Certificate selfSigned(final KeyPair kp, final String dn) throws Exception {
        final long now = System.currentTimeMillis();
        final org.bouncycastle.asn1.x500.X500Name name = new org.bouncycastle.asn1.x500.X500Name(dn);
        final JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                name, BigInteger.valueOf(now), new Date(now - 60_000), new Date(now + 86_400_000L), name, kp.getPublic());
        return new JcaX509CertificateConverter().getCertificate(
                builder.build(new JcaContentSignerBuilder("SHA256withRSA").build(kp.getPrivate())));
    }

    private static String pem(final X509Certificate cert) throws Exception {
        return "-----BEGIN CERTIFICATE-----\n"
                + Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(cert.getEncoded())
                + "\n-----END CERTIFICATE-----\n";
    }
}
