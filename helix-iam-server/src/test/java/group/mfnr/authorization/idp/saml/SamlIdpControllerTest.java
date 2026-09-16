package group.mfnr.authorization.idp.saml;

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
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.Issuer;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.ui.ConcurrentModel;
import org.springframework.ui.Model;

import javax.xml.namespace.QName;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Helix IAM E7.1: the SAML IdP SSO endpoint. For an authenticated user + a registered relying party,
 * it issues a signed Response to the SP's ACS — proven by validating that Response with the SP-side
 * validator (round-trip). An unregistered SP is rejected; an unauthenticated request is bounced to login.
 */
class SamlIdpControllerTest {

    private static final String IDP_ENTITY = "https://helix.test/idp";
    private static final String SP_ENTITY = "https://rp.example/sp";
    private static final String ACS = "https://rp.example/acs";
    private static final String AUTHN_CTX = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport";

    private static final String SP_SLO = "https://rp.example/slo";

    private static String idpCertPem;
    private static String idpKeyPem;
    private static KeyPair idpKeyPair;
    private static String spCertPem;
    private static String spKeyPem;
    private static String otherKeyPem;

    @BeforeAll
    static void init() throws Exception {
        InitializationService.initialize();
        final KeyPair idpKey = rsa();
        idpKeyPair = idpKey;
        idpCertPem = pem(selfSigned(idpKey, "CN=HelixIdP"));
        idpKeyPem = pkcs8Pem(idpKey.getPrivate());
        final KeyPair spKey = rsa();
        spCertPem = pem(selfSigned(spKey, "CN=SP"));
        spKeyPem = pkcs8Pem(spKey.getPrivate());
        otherKeyPem = pkcs8Pem(rsa().getPrivate());
    }

    private SamlIdpController controller() {
        return controller(new SamlIdpProperties.RelyingParty(SP_ENTITY, ACS, AUTHN_CTX, null, null));
    }

    private SamlIdpController controller(final SamlIdpProperties.RelyingParty... rps) {
        final SamlIdpProperties props = new SamlIdpProperties();
        props.setEnabled(true);
        props.setEntityId(IDP_ENTITY);
        props.setSigningCertificate(idpCertPem);
        props.setSigningPrivateKey(idpKeyPem);
        props.setRelyingParties(List.of(rps));
        // Per-realm signing: the credential source derives the IdP cert from the realm's active key. Back it
        // with the SAME key the SP validator trusts (idpCertPem wraps this key), so signatures still verify.
        final group.mfnr.authorization.amqp.ServiceProviderPublisher keyPublisher =
                org.mockito.Mockito.mock(group.mfnr.authorization.amqp.ServiceProviderPublisher.class);
        org.mockito.Mockito.when(keyPublisher.retrieveKeyPair(org.mockito.ArgumentMatchers.anyString()))
                .thenReturn(idpKeyPair);
        final RealmSamlCredentialSource credentialSource = new RealmSamlCredentialSource(keyPublisher, props);
        return new SamlIdpController(props, new SamlAuthnRequestParser(), new SamlAssertionIssuer(), IDP_ENTITY,
                new SamlLogoutRequestParser(), new SamlLogoutRequestIssuer(), new SamlLogoutResponseIssuer(),
                org.mockito.Mockito.mock(group.mfnr.authorization.session.SsoLogoutService.class),
                credentialSource,
                realmId -> java.util.List.of(), // relying parties come from the static props in this test
                org.mockito.Mockito.mock(group.mfnr.authorization.service.UserInfoService.class));
    }

    /** A LogoutRequest as the SP would send it — signed with the given key, issued by the SP, naming the user. */
    private static String spLogoutRequest(final String nameId, final String signingKeyPem) {
        return new SamlLogoutRequestIssuer().issueLogoutRequest(
                new SamlIdpConfig(SP_ENTITY, spCertPem, signingKeyPem), "https://helix.test/saml/idp/slo", nameId);
    }

    @Test
    void slo_terminatesAndReturnsASignedLogoutResponse_forAValidlySignedRequest() throws Exception {
        final SamlIdpController controller = controller(
                new SamlIdpProperties.RelyingParty(SP_ENTITY, ACS, AUTHN_CTX, SP_SLO, spCertPem));

        final Model model = new ConcurrentModel();
        final String view = controller.processSlo(spLogoutRequest("ada@corp", spKeyPem), "rs-1", false,
                new MockHttpServletRequest(), model);

        assertThat(view).isEqualTo("flow/saml-post");
        assertThat(model.getAttribute("action")).isEqualTo(SP_SLO);
        @SuppressWarnings("unchecked") final Map<String, String> fields = (Map<String, String>) model.getAttribute("fields");
        assertThat(fields).containsEntry("RelayState", "rs-1").containsKey("SAMLResponse");
        // The returned LogoutResponse is a genuine, IdP-signed Success.
        final org.opensaml.saml.saml2.core.LogoutResponse resp = parseLogoutResponse(fields.get("SAMLResponse"));
        assertThat(resp.getStatus().getStatusCode().getValue())
                .isEqualTo(org.opensaml.saml.saml2.core.StatusCode.SUCCESS);
    }

    @Test
    void slo_rejectsALogoutRequestSignedWithAMismatchingKey() {
        final SamlIdpController controller = controller(
                new SamlIdpProperties.RelyingParty(SP_ENTITY, ACS, AUTHN_CTX, SP_SLO, spCertPem));

        assertThatThrownBy(() -> controller.processSlo(spLogoutRequest("ada@corp", otherKeyPem), null, false,
                new MockHttpServletRequest(), new ConcurrentModel()))
                .isInstanceOf(IllegalStateException.class);
    }

    @Test
    void slo_rejectsAnUnregisteredRelyingParty() {
        assertThatThrownBy(() -> controller().processSlo(
                new SamlLogoutRequestIssuer().issueLogoutRequest(new SamlIdpConfig("https://evil/sp", spCertPem, spKeyPem),
                        "https://helix.test/saml/idp/slo", "ada@corp"),
                null, false, new MockHttpServletRequest(), new ConcurrentModel()))
                .isInstanceOf(IllegalStateException.class);
    }

    @Test
    void metadataAdvertisesTheSingleLogoutServiceEndpoint() {
        assertThat(controller().metadata(null)).contains("SingleLogoutService")
                .contains("/realms/master/saml/idp/slo");
    }

    private static org.opensaml.saml.saml2.core.LogoutResponse parseLogoutResponse(final String encoded) throws Exception {
        final byte[] xml = Base64.getDecoder().decode(encoded);
        final org.w3c.dom.Element el = XMLObjectProviderRegistrySupport.getParserPool()
                .parse(new java.io.ByteArrayInputStream(xml)).getDocumentElement();
        return (org.opensaml.saml.saml2.core.LogoutResponse) XMLObjectProviderRegistrySupport
                .getUnmarshallerFactory().getUnmarshaller(el).unmarshall(el);
    }

    @Test
    void issuesASignedResponseToTheRegisteredSpForAnAuthenticatedUser() {
        final Model model = new ConcurrentModel();
        final TestingAuthenticationToken auth = new TestingAuthenticationToken("ada@corp", null, "ROLE_USER");
        auth.setAuthenticated(true);

        final String view = controller().processSso(authnRequest(SP_ENTITY), "relay-1", false, auth, model);

        assertThat(view).isEqualTo("flow/saml-post");
        assertThat(model.getAttribute("action")).isEqualTo(ACS);
        @SuppressWarnings("unchecked") final Map<String, String> fields =
                (Map<String, String>) model.getAttribute("fields");
        assertThat(fields).containsEntry("RelayState", "relay-1").containsKey("SAMLResponse");

        // Round-trip: the issued Response validates as a genuine IdP assertion for our subject.
        final SamlAssertionValidator.ValidatedAssertion validated =
                new OpenSamlAssertionValidator(new InMemorySamlAssertionReplayCache())
                        .validate(spConfig(), fields.get("SAMLResponse"), "relay-1");
        assertThat(validated.nameId()).isEqualTo("ada@corp");
    }

    @Test
    void rejectsAnUnregisteredRelyingParty() {
        final TestingAuthenticationToken auth = new TestingAuthenticationToken("ada@corp", null, "ROLE_USER");
        auth.setAuthenticated(true);

        assertThatThrownBy(() -> controller().processSso(authnRequest("https://evil/sp"), null, false, auth, new ConcurrentModel()))
                .isInstanceOf(IllegalStateException.class);
    }

    @Test
    void bouncesAnUnauthenticatedRequestToLogin() {
        assertThat(controller().processSso(authnRequest(SP_ENTITY), null, false, null, new ConcurrentModel()))
                .isEqualTo("redirect:/login");
    }

    @Test
    void publishesIdpMetadataWithTheSigningCertAndSsoEndpoints() {
        final String metadata = controller().metadata(null);
        assertThat(metadata).contains("entityID=\"" + IDP_ENTITY + "\"")
                .contains("IDPSSODescriptor").contains("SingleSignOnService")
                // MT-4: the published SSO endpoint is realm-prefixed (admin realm when none is bound).
                .contains("/realms/master/saml/idp/sso");
    }

    // --- helpers -----------------------------------------------------------------------------------

    private static SamlProviderConfig spConfig() {
        return new SamlProviderConfig("helix-idp", "Helix", IDP_ENTITY + "/saml/idp/sso", IDP_ENTITY,
                SP_ENTITY, ACS, idpCertPem, "mail", "givenName", "sn");
    }

    private static String authnRequest(final String spEntityId) {
        final Issuer issuer = build(Issuer.DEFAULT_ELEMENT_NAME);
        issuer.setValue(spEntityId);
        final AuthnRequest authnRequest = build(AuthnRequest.DEFAULT_ELEMENT_NAME);
        authnRequest.setID("_req-1");
        authnRequest.setVersion(org.opensaml.saml.common.SAMLVersion.VERSION_20);
        authnRequest.setIssueInstant(java.time.Instant.now());
        authnRequest.setIssuer(issuer);
        try {
            final var dom = XMLObjectProviderRegistrySupport.getMarshallerFactory()
                    .getMarshaller(authnRequest).marshall(authnRequest);
            final String xml = net.shibboleth.utilities.java.support.xml.SerializeSupport.nodeToString(dom);
            return Base64.getEncoder().encodeToString(xml.getBytes(StandardCharsets.UTF_8));
        } catch (final Exception e) {
            throw new IllegalStateException(e);
        }
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
