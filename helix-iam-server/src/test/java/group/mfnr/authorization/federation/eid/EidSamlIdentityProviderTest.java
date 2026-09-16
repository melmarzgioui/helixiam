package group.mfnr.authorization.federation.eid;

import group.mfnr.authorization.federation.spi.BrokeredIdentity;
import group.mfnr.authorization.federation.spi.IdentityProvider;
import group.mfnr.authorization.federation.spi.IdpMetadata;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.opensaml.core.config.InitializationService;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.Unmarshaller;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.security.impl.SAMLSignatureProfileValidator;
import org.opensaml.security.x509.BasicX509Credential;
import org.opensaml.xmlsec.signature.support.SignatureValidator;
import org.w3c.dom.Element;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Helix IAM E6.3: the DigiD/eID SAML connector on the federation SPI. {@code start} builds an
 * AuthnRequest carrying the minimum RequestedAuthnContext, enveloped-XML-signs it with the SP key,
 * and returns it over the HTTP-POST binding (DigiD/eHerkenning require POST + enveloped signature);
 * {@code callback} validates the encrypted Response via {@link EidAssertionValidator} and maps it to a
 * {@link BrokeredIdentity} (BSN as external subject; no email → JIT-only). Offline.
 */
class EidSamlIdentityProviderTest {

    private static final String SSO = "https://digid.example/sso";
    private static final String SP_ENTITY = "https://helix.test/sp";
    private static final String DIGID_SUBSTANTIAL = "urn:nl-eid-gdi:1.0:LoA:Substantial";
    private static final String LEGACY_BSN = "urn:nl-eid-gdi:1.0:id:legacy-BSN";
    private static final String EIDAS_SUBSTANTIAL = "http://eidas.europa.eu/LoA/substantial";
    private static final String EIDAS_EXT_NS = "http://eidas.europa.eu/saml-extensions";
    private static final String ATTR_NAME_FORMAT_URI = "urn:oasis:names:tc:SAML:2.0:attrname-format:uri";
    private static final String NP = "http://eidas.europa.eu/attributes/naturalperson/";

    private final EidAssertionValidator validator = mock(EidAssertionValidator.class);
    private final EidArtifactResolver artifactResolver = mock(EidArtifactResolver.class);
    private static final String ARS = "https://digid.example/ars";

    private static KeyPair spPair;
    private static X509Certificate spCertificate;

    @BeforeAll
    static void init() throws Exception {
        InitializationService.initialize();
        final KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        spPair = kpg.generateKeyPair();
        final long now = System.currentTimeMillis();
        final org.bouncycastle.asn1.x500.X500Name name = new org.bouncycastle.asn1.x500.X500Name("CN=HelixSP");
        final JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                name, BigInteger.valueOf(now), new Date(now - 60_000), new Date(now + 86_400_000L), name, spPair.getPublic());
        final ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(spPair.getPrivate());
        final X509CertificateHolder holder = builder.build(signer);
        spCertificate = new JcaX509CertificateConverter().getCertificate(holder);
    }

    private static String spKeyPem() {
        return "-----BEGIN PRIVATE KEY-----\n"
                + Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(spPair.getPrivate().getEncoded())
                + "\n-----END PRIVATE KEY-----\n";
    }

    private static String spCertPem() throws Exception {
        return "-----BEGIN CERTIFICATE-----\n"
                + Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(spCertificate.getEncoded())
                + "\n-----END CERTIFICATE-----\n";
    }

    private EidProviderConfig config() throws Exception {
        return new EidProviderConfig(EidScheme.DIGID, "digid", "DigiD", SSO,
                "https://digid.example/entity", SP_ENTITY, "https://helix.test/acs",
                "idp-cert", "sp-decrypt-key", spKeyPem(), spCertPem(), DIGID_SUBSTANTIAL, null);
    }

    private EidProviderConfig eidasConfig() throws Exception {
        return new EidProviderConfig(EidScheme.EIDAS, "eidas", "eIDAS", SSO,
                "https://eidas.example/entity", SP_ENTITY, "https://helix.test/acs",
                "idp-cert", "sp-decrypt-key", spKeyPem(), spCertPem(), EIDAS_SUBSTANTIAL, null);
    }

    /** Classic DigiD (Koppelvlak SAML): the assertion comes back via the back-channel artifact binding. */
    private EidProviderConfig artifactConfig() throws Exception {
        return new EidProviderConfig(EidScheme.DIGID, "digid-artifact", "DigiD (classic)", SSO,
                "https://digid.example/entity", SP_ENTITY, "https://helix.test/acs",
                "idp-cert", "sp-decrypt-key", spKeyPem(), spCertPem(), DIGID_SUBSTANTIAL, null,
                EidProviderConfig.Binding.POST, null, EidProviderConfig.ResponseBinding.ARTIFACT, ARS);
    }

    private static Map<String, String> queryParams(final String location) {
        final Map<String, String> map = new HashMap<>();
        final String query = location.substring(location.indexOf('?') + 1);
        for (final String pair : query.split("&")) {
            final int i = pair.indexOf('=');
            map.put(pair.substring(0, i),
                    java.net.URLDecoder.decode(pair.substring(i + 1), java.nio.charset.StandardCharsets.UTF_8));
        }
        return map;
    }

    private static String enc(final String value) {
        return java.net.URLEncoder.encode(value, java.nio.charset.StandardCharsets.UTF_8);
    }

    @Test
    void metadataIsSaml2() throws Exception {
        final EidSamlIdentityProvider provider = new EidSamlIdentityProvider(config(), validator);
        assertThat(provider.metadata().alias()).isEqualTo("digid");
        assertThat(provider.metadata().protocol()).isEqualTo(IdpMetadata.Protocol.SAML2);
    }

    @Test
    void startBuildsAnEnvelopedSignedAuthnRequestOverThePostBinding() throws Exception {
        final EidSamlIdentityProvider provider = new EidSamlIdentityProvider(config(), validator);

        final IdentityProvider.RedirectResponse redirect =
                provider.start(new IdentityProvider.AuthnRequestContext("master", "state-123", "https://helix.test/acs"));

        // HTTP-POST binding: an auto-submit form to the IdP SSO with SAMLRequest + RelayState.
        assertThat(redirect.binding()).isEqualTo(IdentityProvider.Binding.POST);
        assertThat(redirect.location()).isEqualTo(SSO);
        assertThat(redirect.formFields()).containsEntry("RelayState", "state-123").containsKey("SAMLRequest");

        // The SAMLRequest is base64 of a signed AuthnRequest naming our SP issuer + the minimum AuthnContext.
        final AuthnRequest authnRequest = parseAuthnRequest(redirect.formFields().get("SAMLRequest"));
        assertThat(authnRequest.getIssuer().getValue()).isEqualTo(SP_ENTITY);
        assertThat(authnRequest.getDestination()).isEqualTo(SSO);
        assertThat(authnRequest.getRequestedAuthnContext().getAuthnContextClassRefs().get(0).getURI())
                .isEqualTo(DIGID_SUBSTANTIAL);

        // The enveloped signature is real and verifies with the SP certificate.
        assertThat(authnRequest.getSignature()).isNotNull();
        new SAMLSignatureProfileValidator().validate(authnRequest.getSignature());
        SignatureValidator.validate(authnRequest.getSignature(), new BasicX509Credential(spCertificate));
    }

    @Test
    void classicV3xUsesTheRedirectBindingWithADetachedQuerySignature() throws Exception {
        final EidProviderConfig redirectConfig = new EidProviderConfig(EidScheme.DIGID, "digid-classic", "DigiD (classic)",
                SSO, "https://digid.example/entity", SP_ENTITY, "https://helix.test/acs", "idp-cert", "sp-decrypt-key",
                spKeyPem(), spCertPem(), DIGID_SUBSTANTIAL, null, EidProviderConfig.Binding.REDIRECT);
        final EidSamlIdentityProvider provider = new EidSamlIdentityProvider(redirectConfig, validator);

        final IdentityProvider.RedirectResponse redirect =
                provider.start(new IdentityProvider.AuthnRequestContext("master", "state-123", "https://helix.test/acs"));

        // HTTP-Redirect binding: a 302 to the IdP SSO with the signed query, not a POST form.
        assertThat(redirect.binding()).isEqualTo(IdentityProvider.Binding.REDIRECT);
        assertThat(redirect.location()).startsWith(SSO + "?SAMLRequest=");

        final Map<String, String> q = queryParams(redirect.location());
        assertThat(q).containsEntry("RelayState", "state-123").containsKey("SigAlg").containsKey("Signature");
        // The detached signature verifies with the SP public key over the canonical query.
        final String signingInput = "SAMLRequest=" + enc(q.get("SAMLRequest"))
                + "&RelayState=" + enc(q.get("RelayState")) + "&SigAlg=" + enc(q.get("SigAlg"));
        final java.security.Signature verifier = java.security.Signature.getInstance("SHA256withRSA");
        verifier.initVerify(spPair.getPublic());
        verifier.update(signingInput.getBytes(java.nio.charset.StandardCharsets.UTF_8));
        assertThat(verifier.verify(Base64.getDecoder().decode(q.get("Signature")))).isTrue();
    }

    @Test
    void callbackValidatesTheResponseAndMapsTheBsnToABrokeredIdentity() throws Exception {
        final EidSamlIdentityProvider provider = new EidSamlIdentityProvider(config(), validator);
        when(validator.validate(any(), eq("encoded-response"), eq("state-123")))
                .thenReturn(new EidAssertion("123456782", LEGACY_BSN, DIGID_SUBSTANTIAL, Map.of("firstName", "Ada")));

        final Map<String, String> params = new HashMap<>();
        params.put("SAMLResponse", "encoded-response");
        params.put("RelayState", "state-123");
        final BrokeredIdentity identity = provider.callback(new IdentityProvider.CallbackContext(
                "master", params, "state-123", null, "https://helix.test/acs"));

        assertThat(identity.idpAlias()).isEqualTo("digid");
        assertThat(identity.externalSubject()).isEqualTo("123456782"); // BSN
        assertThat(identity.email()).isNull();
        assertThat(identity.emailVerified()).isFalse();
        assertThat(identity.attributes()).containsEntry("firstName", "Ada")
                .containsEntry("loa", DIGID_SUBSTANTIAL).containsEntry("subjectType", LEGACY_BSN);
    }

    @Test
    void callbackSurfacesRepresentationContext() throws Exception {
        final EidSamlIdentityProvider provider = new EidSamlIdentityProvider(config(), validator);
        when(validator.validate(any(), eq("encoded-response"), eq("state-123"))).thenReturn(new EidAssertion(
                "90001354", "urn:etoegang:1.9:EntityConcernedID:KvKnr", DIGID_SUBSTANTIAL, Map.of(),
                new EidAssertion.Representation("123456782", "urn:service:42")));

        final Map<String, String> params = new HashMap<>();
        params.put("SAMLResponse", "encoded-response");
        params.put("RelayState", "state-123");
        final BrokeredIdentity identity = provider.callback(new IdentityProvider.CallbackContext(
                "master", params, "state-123", null, "https://helix.test/acs"));

        assertThat(identity.externalSubject()).isEqualTo("90001354"); // the represented company
        assertThat(identity.attributes()).containsEntry("actingSubject", "123456782") // the representative
                .containsEntry("serviceId", "urn:service:42").containsEntry("representation", "true");
    }

    @Test
    void callbackRejectsARelayStateMismatch() throws Exception {
        final EidSamlIdentityProvider provider = new EidSamlIdentityProvider(config(), validator);
        final Map<String, String> params = new HashMap<>();
        params.put("SAMLResponse", "x");
        params.put("RelayState", "attacker");

        assertThatThrownBy(() -> provider.callback(new IdentityProvider.CallbackContext(
                "master", params, "state-123", null, "https://helix.test/acs")))
                .isInstanceOf(IllegalStateException.class);
    }

    @Test
    void artifactBindingResolvesTheAssertionOverTheBackChannelThenValidates() throws Exception {
        final EidSamlIdentityProvider provider = new EidSamlIdentityProvider(artifactConfig(), validator, artifactResolver);
        // The IdP returned only a SAMLart; the resolver fetches the signed Response over the back-channel.
        when(artifactResolver.resolve(any(), eq("art-abc"))).thenReturn("resolved-response-b64");
        when(validator.validate(any(), eq("resolved-response-b64"), eq("state-123")))
                .thenReturn(new EidAssertion("123456782", LEGACY_BSN, DIGID_SUBSTANTIAL, Map.of("firstName", "Ada")));

        final Map<String, String> params = new HashMap<>();
        params.put("SAMLart", "art-abc");
        params.put("RelayState", "state-123");
        final BrokeredIdentity identity = provider.callback(new IdentityProvider.CallbackContext(
                "master", params, "state-123", null, "https://helix.test/acs"));

        assertThat(identity.externalSubject()).isEqualTo("123456782");
        org.mockito.Mockito.verify(artifactResolver).resolve(any(), eq("art-abc"));
    }

    @Test
    void artifactBindingRejectsACallbackWithoutAnArtifact() throws Exception {
        final EidSamlIdentityProvider provider = new EidSamlIdentityProvider(artifactConfig(), validator, artifactResolver);
        final Map<String, String> params = new HashMap<>();
        params.put("RelayState", "state-123"); // no SAMLart

        assertThatThrownBy(() -> provider.callback(new IdentityProvider.CallbackContext(
                "master", params, "state-123", null, "https://helix.test/acs")))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void federatedLogoutSendsASignedLogoutRequestToTheSloEndpoint() throws Exception {
        final EidProviderConfig withSlo = new EidProviderConfig(EidScheme.DIGID, "digid", "DigiD", SSO,
                "https://digid.example/entity", SP_ENTITY, "https://helix.test/acs", "idp-cert", "sp-decrypt-key",
                spKeyPem(), spCertPem(), DIGID_SUBSTANTIAL, null, EidProviderConfig.Binding.POST, null,
                EidProviderConfig.ResponseBinding.POST, null, "https://digid.example/slo");
        final java.util.concurrent.atomic.AtomicReference<String> got = new java.util.concurrent.atomic.AtomicReference<>();
        final group.mfnr.authorization.federation.UpstreamLogoutClient capture = got::set;
        final EidSamlIdentityProvider provider = new EidSamlIdentityProvider(withSlo, validator, artifactResolver,
                capture, () -> "_lr-1", java.time.Instant::now);

        provider.logout(new IdentityProvider.LogoutContext("master", "u1", "digid", null, "bsn-123", "sess-7"));

        assertThat(got.get()).startsWith("https://digid.example/slo?")
                .contains("SAMLRequest=").contains("SigAlg=").contains("Signature=");
    }

    @Test
    void artifactBindingAsksTheIdpForTheArtifactProtocolBinding() throws Exception {
        final EidSamlIdentityProvider provider = new EidSamlIdentityProvider(artifactConfig(), validator, artifactResolver);
        final IdentityProvider.RedirectResponse redirect =
                provider.start(new IdentityProvider.AuthnRequestContext("master", "state-123", "https://helix.test/acs"));
        final AuthnRequest authnRequest = parseAuthnRequest(redirect.formFields().get("SAMLRequest"));
        assertThat(authnRequest.getProtocolBinding()).isEqualTo("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact");
    }

    /**
     * A5: for the eIDAS scheme the outbound AuthnRequest must carry the eIDAS SAML extensions —
     * {@code <eidas:SPType>} and {@code <eidas:RequestedAttributes>} for the minimum-dataset natural-person
     * attributes — and the RequestedAuthnContext must use the eIDAS LoA URN. The enveloped signature must
     * still cover the extensions (they are added before signing).
     */
    @Test
    void eidasStartAddsSpTypeAndRequestedAttributesExtensions() throws Exception {
        final EidSamlIdentityProvider provider = new EidSamlIdentityProvider(eidasConfig(), validator);

        final IdentityProvider.RedirectResponse redirect =
                provider.start(new IdentityProvider.AuthnRequestContext("master", "state-123", "https://helix.test/acs"));
        final AuthnRequest authnRequest = parseAuthnRequest(redirect.formFields().get("SAMLRequest"));

        // The eIDAS LoA URN drives the RequestedAuthnContext.
        assertThat(authnRequest.getRequestedAuthnContext().getAuthnContextClassRefs().get(0).getURI())
                .isEqualTo(EIDAS_SUBSTANTIAL);

        // samlp:Extensions carries eidas:SPType (default "public") and eidas:RequestedAttributes.
        assertThat(authnRequest.getExtensions()).isNotNull();
        final org.opensaml.core.xml.schema.XSAny spType =
                eidasChild(authnRequest.getExtensions().getUnknownXMLObjects(), "SPType");
        assertThat(spType).isNotNull();
        assertThat(spType.getElementQName().getNamespaceURI()).isEqualTo(EIDAS_EXT_NS);
        assertThat(spType.getTextContent()).isEqualTo("public");

        final org.opensaml.core.xml.schema.XSAny requestedAttributes =
                eidasChild(authnRequest.getExtensions().getUnknownXMLObjects(), "RequestedAttributes");
        assertThat(requestedAttributes).isNotNull();
        assertThat(requestedAttributes.getElementQName().getNamespaceURI()).isEqualTo(EIDAS_EXT_NS);

        final Map<String, Boolean> requiredByName = new HashMap<>();
        final Map<String, String> nameFormatByName = new HashMap<>();
        for (final org.opensaml.core.xml.XMLObject child : requestedAttributes.getUnknownXMLObjects()) {
            final org.opensaml.core.xml.schema.XSAny ra = (org.opensaml.core.xml.schema.XSAny) child;
            assertThat(ra.getElementQName().getLocalPart()).isEqualTo("RequestedAttribute");
            final String name = ra.getUnknownAttributes().get(new javax.xml.namespace.QName("Name"));
            requiredByName.put(name, Boolean.valueOf(
                    ra.getUnknownAttributes().get(new javax.xml.namespace.QName("isRequired"))));
            nameFormatByName.put(name, ra.getUnknownAttributes().get(new javax.xml.namespace.QName("NameFormat")));
        }

        // The four mandatory minimum-dataset attributes are requested as required.
        assertThat(requiredByName).containsEntry(NP + "PersonIdentifier", true)
                .containsEntry(NP + "CurrentFamilyName", true)
                .containsEntry(NP + "CurrentGivenName", true)
                .containsEntry(NP + "DateOfBirth", true);
        // Optional attributes are requested but not required.
        assertThat(requiredByName).containsEntry(NP + "CurrentAddress", false)
                .containsEntry(NP + "PlaceOfBirth", false)
                .containsEntry(NP + "Gender", false);
        // Every RequestedAttribute uses the SAML URI NameFormat.
        assertThat(nameFormatByName.values()).allMatch(ATTR_NAME_FORMAT_URI::equals);

        // The enveloped signature still verifies with the SP certificate (it covers the extensions).
        assertThat(authnRequest.getSignature()).isNotNull();
        new SAMLSignatureProfileValidator().validate(authnRequest.getSignature());
        SignatureValidator.validate(authnRequest.getSignature(), new BasicX509Credential(spCertificate));
    }

    /** DigiD (and eHerkenning) requests must NOT carry the eIDAS-only extensions. */
    @Test
    void nonEidasSchemesGetNoEidasExtensions() throws Exception {
        final EidSamlIdentityProvider provider = new EidSamlIdentityProvider(config(), validator);
        final IdentityProvider.RedirectResponse redirect =
                provider.start(new IdentityProvider.AuthnRequestContext("master", "state-123", "https://helix.test/acs"));

        final AuthnRequest authnRequest = parseAuthnRequest(redirect.formFields().get("SAMLRequest"));
        assertThat(authnRequest.getExtensions()).isNull();
        final String xml = new String(Base64.getDecoder().decode(redirect.formFields().get("SAMLRequest")),
                java.nio.charset.StandardCharsets.UTF_8);
        assertThat(xml).doesNotContain(EIDAS_EXT_NS);
    }

    @SuppressWarnings("unchecked")
    private static <T> T eidasChild(final java.util.List<org.opensaml.core.xml.XMLObject> objects, final String localName) {
        return (T) objects.stream()
                .filter(o -> o instanceof org.opensaml.core.xml.schema.XSAny)
                .filter(o -> localName.equals(o.getElementQName().getLocalPart()))
                .findFirst().orElse(null);
    }

    private static AuthnRequest parseAuthnRequest(final String samlRequestBase64) throws Exception {
        final byte[] xml = Base64.getDecoder().decode(samlRequestBase64);
        final Element element = XMLObjectProviderRegistrySupport.getParserPool()
                .parse(new ByteArrayInputStream(xml)).getDocumentElement();
        final Unmarshaller unmarshaller = XMLObjectProviderRegistrySupport.getUnmarshallerFactory().getUnmarshaller(element);
        return (AuthnRequest) unmarshaller.unmarshall(element);
    }
}
