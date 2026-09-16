package group.mfnr.authorization.idp.saml;

import group.mfnr.authorization.amqp.saml.SamlSpOptions;
import group.mfnr.authorization.federation.saml.InMemorySamlAssertionReplayCache;
import group.mfnr.authorization.federation.saml.OpenSamlAssertionValidator;
import group.mfnr.authorization.federation.saml.SamlAssertionValidator;
import group.mfnr.authorization.federation.saml.SamlProviderConfig;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.opensaml.core.config.InitializationService;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Date;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Helix IAM E7.1: Helix as a SAML2 IdP. {@link SamlAssertionIssuer} builds a genuinely XML-signed
 * SAML Response for a relying party. Proven by a full round-trip: issue a Response, then validate it
 * with the E5.2 SP-side {@link OpenSamlAssertionValidator} — Helix signs as IdP, the validator
 * verifies against Helix's cert, and the NameID + attributes + audience come back intact. Also proves
 * a tampered audience is rejected. Fully offline.
 */
class SamlAssertionIssuerTest {

    private static final String IDP_ENTITY = "https://helix.test/idp";
    private static final String SP_ENTITY = "https://rp.example/sp";
    private static final String ACS = "https://rp.example/acs";
    private static final String AUTHN_CTX = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport";

    private static KeyPair idpKey;
    private static String idpCertPem;
    private static String idpKeyPem;

    private final SamlAssertionIssuer issuer = new SamlAssertionIssuer();

    @BeforeAll
    static void init() throws Exception {
        InitializationService.initialize();
        idpKey = rsa();
        final X509Certificate idpCert = selfSigned(idpKey, "CN=HelixIdP");
        idpCertPem = pem(idpCert);
        idpKeyPem = pkcs8Pem(idpKey.getPrivate());
    }

    @Test
    void issuesASignedResponseThatTheSpValidatorAccepts() {
        final SamlIdpConfig idp = new SamlIdpConfig(IDP_ENTITY, idpCertPem, idpKeyPem);

        final String response = issuer.issueResponse(idp, SP_ENTITY, ACS, "ada@corp",
                Map.of("mail", "ada@corp"), AUTHN_CTX, "_req-123", SamlSpOptions.defaults());

        final SamlAssertionValidator.ValidatedAssertion validated =
                new OpenSamlAssertionValidator(new InMemorySamlAssertionReplayCache())
                        .validate(spConfig(), response, "relay");

        assertThat(validated.nameId()).isEqualTo("ada@corp");
        assertThat(validated.attributes()).containsEntry("mail", "ada@corp");
    }

    @Test
    void signsTheResponseAndCarriesBearerSubjectConfirmationWhenConfigured() {
        final SamlIdpConfig idp = new SamlIdpConfig(IDP_ENTITY, idpCertPem, idpKeyPem);
        // signResponse on, default signAssertion on — the SP-side validator (assertion sig) still accepts it.
        final SamlSpOptions opts = new SamlSpOptions(null, true, null, null, null, null, "RSA_SHA256",
                "SHA256", null, null, null, null, null, null, null, 600);

        final String response = issuer.issueResponse(idp, SP_ENTITY, ACS, "ada@corp",
                Map.of("mail", "ada@corp"), AUTHN_CTX, "_req-xyz", opts);

        final String xml = new String(Base64.getDecoder().decode(response), java.nio.charset.StandardCharsets.UTF_8);
        assertThat(xml).contains("SubjectConfirmation");
        assertThat(xml).contains("urn:oasis:names:tc:SAML:2.0:cm:bearer");
        assertThat(xml).contains("Recipient=\"" + ACS + "\"");

        final SamlAssertionValidator.ValidatedAssertion validated =
                new OpenSamlAssertionValidator(new InMemorySamlAssertionReplayCache())
                        .validate(spConfig(), response, "relay");
        assertThat(validated.nameId()).isEqualTo("ada@corp");
    }

    @Test
    void aResponseForAnotherAudienceIsRejectedByTheSp() {
        final SamlIdpConfig idp = new SamlIdpConfig(IDP_ENTITY, idpCertPem, idpKeyPem);

        final String response = issuer.issueResponse(idp, "https://someone-else/sp", ACS, "ada@corp",
                Map.of(), AUTHN_CTX, "_req-123", SamlSpOptions.defaults());

        assertThatThrownBy(() -> new OpenSamlAssertionValidator(new InMemorySamlAssertionReplayCache())
                .validate(spConfig(), response, "relay")).isInstanceOf(IllegalStateException.class);
    }

    private static SamlProviderConfig spConfig() {
        // The RP/SP view of Helix: expect Helix's entity id + cert, our own SP entity id as audience.
        return new SamlProviderConfig("helix-idp", "Helix", IDP_ENTITY + "/sso", IDP_ENTITY,
                SP_ENTITY, ACS, idpCertPem, "mail", "givenName", "sn");
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
        final ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(kp.getPrivate());
        final X509CertificateHolder holder = builder.build(signer);
        return new JcaX509CertificateConverter().getCertificate(holder);
    }

    private static String pem(final X509Certificate cert) throws Exception {
        return "-----BEGIN CERTIFICATE-----\n"
                + Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(cert.getEncoded())
                + "\n-----END CERTIFICATE-----\n";
    }

    private static String pkcs8Pem(final PrivateKey key) {
        return "-----BEGIN PRIVATE KEY-----\n"
                + Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(key.getEncoded())
                + "\n-----END PRIVATE KEY-----\n";
    }
}
