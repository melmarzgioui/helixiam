/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.e2e;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import io.helixiam.authorization.federation.saml.InMemorySamlAssertionReplayCache;
import io.helixiam.authorization.federation.saml.OpenSamlAssertionValidator;
import io.helixiam.authorization.federation.saml.SamlAssertionValidator;
import io.helixiam.authorization.federation.saml.SamlProviderConfig;
import io.helixiam.authorization.idp.saml.RealmSamlCredentialSource;
import io.helixiam.authorization.idp.saml.SamlAssertionIssuer;
import io.helixiam.authorization.idp.saml.SamlIdpConfig;
import io.helixiam.authorization.amqp.saml.SamlSpOptions;
import io.helixiam.authorization.service.key.RealmKeyMaterial;
import io.helixiam.authorization.service.key.RealmKeyService;
import io.helixiam.testsupport.LogCapture;
import io.helixiam.testsupport.TestPki;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.JsonNode;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Bring-your-own realm signing keys, end to end against the real server: a CA-signed key imported as PENDING is
 * published (JWKS {@code x5c}, SAML metadata) but does not sign until activated; the CSR flow; an ES256 realm whose
 * ID tokens a standard verifier accepts; and the refusals (400 on the right field, 404 across realms, 409 on state).
 */
class RealmKeyRolloverE2eTest extends AbstractE2eTest {

    private static final String PASSWORD = "Realm-Key-Passw0rd!";
    private static TestPki.Ca ca;

    @BeforeAll
    static void pki() throws Exception {
        org.opensaml.core.config.InitializationService.initialize();
        ca = TestPki.ca("HelixIAM Test Root CA");
    }

    // ------------------------------------------------------------------------------------------------ import → activate

    @Test
    void importedCaSignedKey_isPublishedPending_thenActivated_andOldTokensStillVerify() throws Exception {
        final String realm = E2eSeed.unique("byo");
        seed().realm(realm);
        final E2eSeed.SeededClient sa = seed().serviceAccountClient(realm, E2eSeed.unique("svc"), List.of("openid"));
        final OidcFlow oidc = oidc(realm);
        final String oldToken = oidc.clientCredentials(sa.clientId(), sa.secret(), "openid").accessToken();
        final String oldKid = kid(oldToken);
        final E2eAdminSession admin = adminSession();

        final KeyPair kp = TestPki.rsa(2048);
        final X509Certificate leaf = TestPki.issue(ca, "CN=" + realm + ".idp.example, O=Example", kp.getPublic(), 365);
        final String privatePem = TestPki.pkcs8(kp.getPrivate());
        final String privateB64 = Base64.getEncoder().encodeToString(kp.getPrivate().getEncoded());
        final JsonNode imported;
        final String keyId;
        try (LogCapture logs = LogCapture.all(); LogCapture auditLog = LogCapture.named("helix.audit")) {
            final E2eHttp.Response r = admin.post(keys(realm) + "/import", Map.of("privateKeyPem", privatePem,
                    "certificateChainPem", TestPki.pem(leaf, ca.certificate())));
            assertThat(r.status()).as(r.toString()).isEqualTo(201);
            assertNoSecrets(r.body(), privatePem, privateB64);
            imported = r.json();
            keyId = imported.path("keyId").asText();
            assertThat(imported.path("status").asText()).isEqualTo("PENDING");
            assertThat(imported.path("source").asText()).isEqualTo("IMPORTED");
            assertThat(imported.path("algorithm").asText()).isEqualTo("RS256");
            assertThat(imported.path("certificate").path("subject").asText()).contains("CN=" + realm + ".idp.example");
            assertThat(imported.path("certificate").path("issuer").asText()).contains("HelixIAM Test Root CA");
            assertThat(imported.path("certificate").path("sha256Fingerprint").asText())
                    .isEqualTo(RealmKeyMaterial.fingerprint(leaf));
            assertThat(imported.path("certificate").path("chainLength").asInt()).isEqualTo(2);
            assertThat(imported.path("certificate").path("expiry").asText()).isEqualTo("OK");
            assertThat(imported.path("certificate").path("notAfter").asLong()).isEqualTo(leaf.getNotAfter().getTime());

            // The list carries the same public facts; the private key never appears anywhere.
            final E2eHttp.Response list = admin.get(keys(realm));
            assertNoSecrets(list.body(), privatePem, privateB64);

            // Activate (after checking the staged state below) — audit for both, with keyId + fingerprint only.
            final String newKid = RealmKeyMaterial.kid(kp.getPublic());
            final JWKSet staged = oidc.jwks();
            final JWK pending = staged.getKeyByKeyId(newKid);
            assertThat(pending).as("PENDING key published in the JWKS").isNotNull();
            assertThat(pending.getX509CertChain()).hasSize(1); // the trailing root is not published
            assertThat(pending.getX509CertChain().get(0).toString())
                    .isEqualTo(Base64.getEncoder().encodeToString(leaf.getEncoded())); // standard Base64 DER
            assertThat(pending.getX509CertSHA256Thumbprint()).isNotNull();
            assertThat(pending.isPrivate()).isFalse();
            assertEveryJwkHasKidAlgUse(staged);
            assertThat(kid(oidc.clientCredentials(sa.clientId(), sa.secret(), "openid").accessToken()))
                    .as("a PENDING key does not sign").isEqualTo(oldKid);

            // SAML metadata already lists the PENDING certificate (after the ACTIVE one).
            final List<String> stagedCerts = metadataSigningCerts(realm);
            assertThat(stagedCerts).hasSize(2);
            assertThat(stagedCerts.get(1)).isEqualTo(Base64.getEncoder().encodeToString(leaf.getEncoded()));

            final E2eHttp.Response activated = admin.post(keys(realm) + "/" + keyId + "/activate?force=true", Map.of());
            assertThat(activated.status()).as(activated.toString()).isEqualTo(200);
            assertThat(activated.json().path("status").asText()).isEqualTo("ACTIVE");

            assertThat(logs.text()).doesNotContain(privateB64.substring(0, 40)).doesNotContain("BEGIN PRIVATE KEY")
                    .doesNotContain(privatePem.substring(30, 90));
            assertThat(auditLog.text()).doesNotContain(privateB64.substring(0, 40)).doesNotContain("PRIVATE KEY");
            final String audit = String.join("\n", auditLog.messages().stream()
                    .filter(m -> m.contains("REALM_KEY_")).toList());
            assertThat(audit).contains("REALM_KEY_IMPORT").contains("REALM_KEY_ACTIVATE").contains(keyId)
                    .contains(RealmKeyMaterial.fingerprint(leaf)).doesNotContain("PRIVATE KEY");
        }

        // The previous key is retained (ROTATED), still published.
        final JsonNode list = admin.get(keys(realm)).json();
        final List<String> statuses = new ArrayList<>();
        list.forEach(k -> statuses.add(k.path("status").asText()));
        assertThat(statuses).containsExactlyInAnyOrder("ACTIVE", "ROTATED");

        // New tokens carry the new kid and verify against the JWKS; the old token still verifies.
        final String newToken = oidc.clientCredentials(sa.clientId(), sa.secret(), "openid").accessToken();
        assertThat(kid(newToken)).isEqualTo(RealmKeyMaterial.kid(kp.getPublic()));
        assertThat(SignedJWT.parse(newToken).getHeader().getAlgorithm()).isEqualTo(JWSAlgorithm.RS256);
        assertThat(oidc.verify(newToken).getSubject()).isEqualTo(sa.clientId());
        assertThat(oidc.verify(oldToken).getSubject()).isEqualTo(sa.clientId());
        assertEveryJwkHasKidAlgUse(oidc.jwks());

        // SAML: metadata leads with the imported leaf; responses are signed with it (verified with OpenSAML).
        final List<String> certs = metadataSigningCerts(realm);
        assertThat(certs.get(0)).isEqualTo(Base64.getEncoder().encodeToString(leaf.getEncoded()));
        assertSamlSignedWith(realm, TestPki.pem(leaf));

        // Retiring the ACTIVE key is refused; retiring the rotated one drops it from the JWKS.
        assertThat(admin.delete(keys(realm) + "/" + keyId).status()).isEqualTo(409);
        final String rotatedId = idWithStatus(admin.get(keys(realm)).json(), "ROTATED");
        assertThat(admin.delete(keys(realm) + "/" + rotatedId).status()).isEqualTo(204);
        assertThat(oidc.jwks().getKeyByKeyId(oldKid)).isNull();
    }

    // ------------------------------------------------------------------------------------------------ CSR

    @Test
    void csrFlow_csrSignedByTheCa_attached_activated() throws Exception {
        final String realm = E2eSeed.unique("csr");
        seed().realm(realm);
        final E2eSeed.SeededClient sa = seed().serviceAccountClient(realm, E2eSeed.unique("svc"), List.of("openid"));
        final OidcFlow oidc = oidc(realm);
        final String oldToken = oidc.clientCredentials(sa.clientId(), sa.secret(), "openid").accessToken();
        final E2eAdminSession admin = adminSession();

        final E2eHttp.Response created = admin.post(keys(realm) + "/csr", Map.of("algorithm", "RS256",
                "subject", "CN=" + realm + ".example.com, O=Example, C=NL", "dnsNames", List.of(realm + ".example.com")));
        assertThat(created.status()).as(created.toString()).isEqualTo(201);
        final String csrPem = created.json().path("csrPem").asText();
        final String keyId = created.json().path("key").path("keyId").asText();
        assertThat(csrPem).startsWith("-----BEGIN CERTIFICATE REQUEST-----");
        assertThat(created.body()).doesNotContain("PRIVATE KEY");
        assertThat(created.json().path("key").path("status").asText()).isEqualTo("PENDING");
        assertThat(created.json().path("key").path("hasCsr").asBoolean()).isTrue();
        assertThat(admin.get(keys(realm) + "/" + keyId + "/csr").json().path("csrPem").asText()).isEqualTo(csrPem);

        // Activating before the certificate is attached is allowed (D24), but here we attach first.
        final X509Certificate signed = TestPki.signCsr(ca, csrPem, 200);
        final E2eHttp.Response attached = admin.put(keys(realm) + "/" + keyId + "/certificate",
                Map.of("certificateChainPem", TestPki.pem(signed, ca.certificate())));
        assertThat(attached.status()).as(attached.toString()).isEqualTo(200);
        assertThat(attached.json().path("certificate").path("sha256Fingerprint").asText())
                .isEqualTo(RealmKeyMaterial.fingerprint(signed));
        final String newKid = RealmKeyMaterial.kid(signed.getPublicKey());
        assertThat(oidc.jwks().getKeyByKeyId(newKid).getX509CertChain()).isNotEmpty();

        assertThat(admin.post(keys(realm) + "/" + keyId + "/activate?force=true", Map.of()).status()).isEqualTo(200);
        final String token = oidc.clientCredentials(sa.clientId(), sa.secret(), "openid").accessToken();
        assertThat(kid(token)).isEqualTo(newKid);
        oidc.verify(token);
        oidc.verify(oldToken);
        assertSamlSignedWith(realm, TestPki.pem(signed));
    }

    // ------------------------------------------------------------------------------------------------ ES256

    @Test
    void es256IsOfferedAlongsideRs256_eachClientGetsItsAlg_accessTokensFollowTheRealmDefault() throws Exception {
        final String realm = E2eSeed.unique("es");
        seed().realm(realm);
        final E2eSeed.SeededClient web = seed().confidentialClient(realm, "web", List.of("openid", "profile"));
        final E2eSeed.SeededClient ecClient = seed().confidentialClient(realm, "ecweb", List.of("openid", "profile"));
        final E2eSeed.SeededUser user = seed().user(realm, E2eSeed.unique("eve"), PASSWORD);
        final E2eSeed.SeededClient sa = seed().serviceAccountClient(realm, E2eSeed.unique("svc"), List.of("openid"));
        final E2eAdminSession admin = adminSession();
        final OidcFlow oidc = oidc(realm);
        assertThat(discoveryAlgs(oidc)).containsExactly("RS256", "PS256");

        // No ACTIVE EC key yet: a client cannot ask for ES256 ID tokens, nor the realm for ES256 by default.
        assertThat(setIdTokenAlg(admin, realm, ecClient, "ES256").status()).isEqualTo(400);
        assertThat(admin.put("/admin/realms/" + realm + "/settings/signing", Map.of("defaultAlg", "ES256",
                "samlAlg", "RS256")).json().path("fieldErrors").has("defaultAlg")).isTrue();

        final KeyPair ec = TestPki.ec("secp256r1");
        final X509Certificate self = TestPki.selfSigned(ec, "CN=" + realm + " ES256", 365);
        final E2eHttp.Response imported = admin.post(keys(realm) + "/import", Map.of(
                "privateKeyPem", TestPki.traditional(ec), "certificateChainPem", TestPki.pem(self)));
        assertThat(imported.status()).as(imported.toString()).isEqualTo(201);
        assertThat(imported.json().path("algorithm").asText()).isEqualTo("ES256");
        final String ecKeyId = imported.json().path("keyId").asText();
        assertThat(discoveryAlgs(oidc)).as("a PENDING key is not advertised").containsExactly("RS256", "PS256");
        assertThat(admin.post(keys(realm) + "/" + ecKeyId + "/activate?force=true", Map.of()).status()).isEqualTo(200);

        // Both families are ACTIVE: discovery lists exactly their algorithms, RS256 first.
        assertThat(discoveryAlgs(oidc)).containsExactly("RS256", "PS256", "ES256");
        final List<String> statuses = new ArrayList<>();
        admin.get(keys(realm)).json().forEach(k -> statuses.add(k.path("algorithm").asText() + ":" + k.path("status").asText()));
        assertThat(statuses).containsExactlyInAnyOrder("RS256:ACTIVE", "ES256:ACTIVE");

        // The default client gets RS256 ID tokens; the client registered for ES256 gets ES256.
        assertThat(setIdTokenAlg(admin, realm, ecClient, "ES256").status()).isEqualTo(200);
        final OidcFlow.Tokens rsTokens = oidc(realm).authorizationCode("web", web.secret(), web.redirectUri(),
                user.username(), PASSWORD, "openid profile");
        assertThat(SignedJWT.parse(rsTokens.idToken()).getHeader().getAlgorithm()).isEqualTo(JWSAlgorithm.RS256);
        final OidcFlow.Tokens esTokens = oidc(realm).authorizationCode("ecweb", ecClient.secret(),
                ecClient.redirectUri(), user.username(), PASSWORD, "openid profile");
        final SignedJWT idToken = SignedJWT.parse(esTokens.idToken());
        assertThat(idToken.getHeader().getAlgorithm()).isEqualTo(JWSAlgorithm.ES256);
        assertThat(idToken.getHeader().getKeyID()).isEqualTo(RealmKeyMaterial.kid(ec.getPublic()));
        // A standard verifier: Nimbus, ES256 only, keys from the published JWKS.
        final DefaultJWTProcessor<SecurityContext> nimbus = new DefaultJWTProcessor<>();
        nimbus.setJWSKeySelector(new JWSVerificationKeySelector<>(JWSAlgorithm.ES256, new ImmutableJWKSet<>(oidc.jwks())));
        final JWTClaimsSet claims = nimbus.process(esTokens.idToken(), null);
        assertThat(claims.getSubject()).isEqualTo(user.userId());
        assertThat(claims.getIssuer()).isEqualTo(oidc.issuer());
        oidc.verify(rsTokens.idToken());

        // Access tokens follow signing.defaultAlg: RS256 by default, ES256 once the realm chooses it.
        assertThat(alg(oidc.clientCredentials(sa.clientId(), sa.secret(), "openid").accessToken())).isEqualTo("RS256");
        assertThat(alg(esTokens.accessToken())).isEqualTo("RS256");
        final E2eHttp.Response settings = admin.put("/admin/realms/" + realm + "/settings/signing",
                Map.of("defaultAlg", "ES256", "samlAlg", "RS256"));
        assertThat(settings.status()).as(settings.toString()).isEqualTo(200);
        final String machine = oidc.clientCredentials(sa.clientId(), sa.secret(), "openid").accessToken();
        assertThat(alg(machine)).isEqualTo("ES256");
        oidc.verify(machine);
        assertThat(alg(oidc(realm).authorizationCode("web", web.secret(), web.redirectUri(), user.username(),
                PASSWORD, "openid profile").idToken())).as("ID tokens keep the client's alg").isEqualTo("RS256");

        // The EC key is in use by the settings: retiring it is refused; the ACTIVE RSA key is never retirable.
        assertThat(admin.delete(keys(realm) + "/" + ecKeyId).status()).isEqualTo(409);
        final String rsaId = idWithAlgAndStatus(admin.get(keys(realm)).json(), "RS256", "ACTIVE");
        assertThat(admin.delete(keys(realm) + "/" + rsaId).status()).isEqualTo(409);

        // SAML signs with the RSA key by default (with an encryption KeyDescriptor); with samlAlg=ES256 it signs
        // ECDSA-SHA256 with the imported EC certificate, verified with OpenSAML, and drops the encryption descriptor.
        assertThat(metadata(realm)).contains("use=\"encryption\"");
        assertThat(assertSamlSignedWith(realm, null)).contains("rsa-sha256");
        assertThat(admin.put("/admin/realms/" + realm + "/settings/signing", Map.of("defaultAlg", "ES256",
                "samlAlg", "ES256")).status()).isEqualTo(200);
        assertThat(metadata(realm)).doesNotContain("use=\"encryption\"");
        assertThat(metadataSigningCerts(realm).get(0)).isEqualTo(Base64.getEncoder().encodeToString(self.getEncoded()));
        assertThat(assertSamlSignedWith(realm, TestPki.pem(self)))
                .contains("http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256");

        // Back to RS256: then the EC key may be retired, and discovery drops ES256 (RS256 is always there).
        assertThat(admin.put("/admin/realms/" + realm + "/settings/signing", Map.of("defaultAlg", "RS256",
                "samlAlg", "RS256")).status()).isEqualTo(200);
        assertThat(admin.delete(keys(realm) + "/" + ecKeyId).status()).isEqualTo(204);
        assertThat(discoveryAlgs(oidc)).containsExactly("RS256", "PS256");
        assertThat(alg(oidc(realm).authorizationCode("ecweb", ecClient.secret(), ecClient.redirectUri(),
                user.username(), PASSWORD, "openid profile").idToken()))
                .as("no ES256 key any more: RS256 with a WARN").isEqualTo("RS256");
        // Its key retired, the ES256 access token no longer verifies — retiring is how a key is withdrawn.
        org.assertj.core.api.Assertions.assertThatThrownBy(() -> oidc.verify(machine)).isInstanceOf(AssertionError.class);
    }

    @Test
    void anEcKeyCannotBeTheOnlyActiveKey_andActivationWaitsForTheStagingTime() {
        final String realm = E2eSeed.unique("stage");
        seed().realm(realm);
        oidc(realm).jwks();
        final E2eAdminSession admin = adminSession();
        final JsonNode csr = admin.post(keys(realm) + "/csr", Map.of("algorithm", "RS256", "subject", "CN=stage"))
                .json();
        final String keyId = csr.path("key").path("keyId").asText();
        assertThat(csr.path("key").path("activatableAt").asLong()).isGreaterThan(System.currentTimeMillis());

        final E2eHttp.Response early = admin.post(keys(realm) + "/" + keyId + "/activate", Map.of());
        assertThat(early.status()).as(early.toString()).isEqualTo(409);
        assertThat(early.json().path("error").asText()).isEqualTo("staging");
        try (LogCapture audit = LogCapture.named("helix.audit")) {
            assertThat(admin.post(keys(realm) + "/" + keyId + "/activate?force=true", Map.of()).status()).isEqualTo(200);
            assertThat(audit.text()).contains("REALM_KEY_ACTIVATE").contains("\"forced\":\"true\"");
        }
    }

    // ------------------------------------------------------------------------------------------------ races

    @Test
    void concurrentActivations_leaveExactlyOneActiveKeyPerFamily() throws Exception {
        final String realm = E2eSeed.unique("race");
        seed().realm(realm);
        oidc(realm).jwks();
        final RealmKeyService service = context.getBean(RealmKeyService.class);
        for (int round = 0; round < 5; round++) {
            final String a = service.createCsr(realm, "RS256", "CN=a" + round, List.of()).key().getKeyId();
            final String b = service.createCsr(realm, "RS256", "CN=b" + round, List.of()).key().getKeyId();
            race(() -> service.activate(realm, a, true), () -> service.activate(realm, b, true));
            assertThat(activeRsa(service, realm)).as("round " + round).hasSize(1);
        }
        for (int round = 0; round < 5; round++) {
            final String p = service.createCsr(realm, "RS256", "CN=p" + round, List.of()).key().getKeyId();
            race(() -> service.activate(realm, p, true), () -> service.retire(realm, p));
            final List<io.helixiam.authorization.domain.realm.RealmKey> active = activeRsa(service, realm);
            assertThat(active).as("round " + round).hasSize(1);
            final String status = service.find(realm, p).orElseThrow().getStatus();
            // Either the activation won (the retire was refused) or the retire won (the activation was refused).
            assertThat(status).isIn("ACTIVE", "RETIRED");
            assertThat(active.get(0).getKeyId().equals(p)).isEqualTo("ACTIVE".equals(status));
        }
        final E2eSeed.SeededClient sa = seed().serviceAccountClient(realm, E2eSeed.unique("svc"), List.of("openid"));
        final OidcFlow oidc = oidc(realm);
        oidc.verify(oidc.clientCredentials(sa.clientId(), sa.secret(), "openid").accessToken());
    }

    private static List<io.helixiam.authorization.domain.realm.RealmKey> activeRsa(final RealmKeyService service,
                                                                                  final String realm) {
        return service.publishedKeys(realm).stream().filter(k -> "ACTIVE".equals(k.getStatus())
                && "RS256".equals(k.getJwsAlgorithm())).toList();
    }

    private static void race(final Runnable one, final Runnable two) throws Exception {
        final java.util.concurrent.CyclicBarrier start = new java.util.concurrent.CyclicBarrier(2);
        final java.util.concurrent.ExecutorService pool = java.util.concurrent.Executors.newFixedThreadPool(2);
        try {
            final List<java.util.concurrent.Future<?>> futures = new ArrayList<>();
            for (final Runnable r : List.of(one, two)) {
                futures.add(pool.submit(() -> {
                    start.await();
                    try {
                        r.run();
                    } catch (final RealmKeyService.KeyStateException | java.util.NoSuchElementException expected) {
                        // the loser of the race is refused — that is the point
                    }
                    return null;
                }));
            }
            for (final java.util.concurrent.Future<?> f : futures) {
                f.get(60, java.util.concurrent.TimeUnit.SECONDS);
            }
        } finally {
            pool.shutdownNow();
        }
    }

    private static List<String> discoveryAlgs(final OidcFlow oidc) {
        final List<String> algs = new ArrayList<>();
        oidc.discovery().path("id_token_signing_alg_values_supported").forEach(a -> algs.add(a.asText()));
        return algs;
    }

    private static String alg(final String jwt) throws Exception {
        return SignedJWT.parse(jwt).getHeader().getAlgorithm().getName();
    }

    private static E2eHttp.Response setIdTokenAlg(final E2eAdminSession admin, final String realm,
                                                  final E2eSeed.SeededClient client, final String alg) {
        final String path = "/admin/realms/" + realm + "/clients/" + client.id();
        final tools.jackson.databind.node.ObjectNode body = (tools.jackson.databind.node.ObjectNode) admin.get(path).json();
        body.remove(List.of("realmId", "id", "secret"));
        body.put("idTokenSignatureAlg", alg);
        return admin.put(path, body);
    }

    private static String idWithAlgAndStatus(final JsonNode list, final String alg, final String status) {
        for (final JsonNode k : list) {
            if (alg.equals(k.path("algorithm").asText()) && status.equals(k.path("status").asText())) {
                return k.path("keyId").asText();
            }
        }
        throw new AssertionError("No " + alg + " " + status + " key in " + list);
    }

    // ------------------------------------------------------------------------------------------------ refusals

    @Test
    void refusals_400OnTheField_404AcrossRealms_409OnState_andNoSecretsInErrors() {
        final String realm = E2eSeed.unique("neg");
        final String other = E2eSeed.unique("neg2");
        seed().realm(realm);
        seed().realm(other);
        final E2eAdminSession admin = adminSession();
        oidc(realm).jwks(); // the realm's generated key exists first
        final KeyPair kp = TestPki.rsa(2048);
        final String kpPem = TestPki.pkcs8(kp.getPrivate());

        // Mismatched key and certificate.
        final X509Certificate foreign = TestPki.issue(ca, "CN=foreign", TestPki.rsa(2048).getPublic(), 90);
        assertField(admin.post(keys(realm) + "/import", Map.of("privateKeyPem", kpPem,
                "certificateChainPem", TestPki.pem(foreign))), "certificateChainPem", "does not match", kpPem);
        // Expired certificate.
        final X509Certificate expired = TestPki.issue(ca.certificate(), ca.keyPair().getPrivate(), "CN=old",
                kp.getPublic(), Instant.now().minus(Duration.ofDays(30)), Instant.now().minus(Duration.ofDays(1)),
                KeyUsage.digitalSignature);
        assertField(admin.post(keys(realm) + "/import", Map.of("privateKeyPem", kpPem,
                "certificateChainPem", TestPki.pem(expired))), "certificateChainPem", "expired", kpPem);
        // Wrong chain order (root first).
        final X509Certificate leaf = TestPki.issue(ca, "CN=order", kp.getPublic(), 90);
        assertField(admin.post(keys(realm) + "/import", Map.of("privateKeyPem", kpPem,
                "certificateChainPem", TestPki.pem(ca.certificate(), leaf))), "certificateChainPem", null, kpPem);
        // Weak RSA.
        final KeyPair weak = TestPki.rsa(1024);
        assertField(admin.post(keys(realm) + "/import", Map.of("privateKeyPem", TestPki.pkcs8(weak.getPrivate()),
                "certificateChainPem", TestPki.pem(TestPki.selfSigned(weak, "CN=weak", 30)))),
                "privateKeyPem", "2048", null);
        // Unsupported curve.
        final KeyPair p384 = TestPki.ec("secp384r1");
        assertField(admin.post(keys(realm) + "/import", Map.of("privateKeyPem", TestPki.pkcs8(p384.getPrivate()),
                "certificateChainPem", TestPki.pem(TestPki.selfSigned(p384, "CN=p384", 30)))),
                "privateKeyPem", "P-256", null);
        // Unknown algorithm / bad subject on CSR.
        assertField(admin.post(keys(realm) + "/csr", Map.of("algorithm", "HS256", "subject", "CN=x")),
                "algorithm", null, null);
        assertField(admin.post(keys(realm) + "/csr", Map.of("algorithm", "RS256", "subject", "nonsense")),
                "subject", null, null);

        // A certificate for another realm's key: realm B's CSR, signed, attached to realm A's key → mismatch.
        final String aKey = admin.post(keys(realm) + "/csr", Map.of("algorithm", "RS256", "subject", "CN=a"))
                .json().path("key").path("keyId").asText();
        final JsonNode bCsr = admin.post(keys(other) + "/csr", Map.of("algorithm", "RS256", "subject", "CN=b")).json();
        final X509Certificate bCert = TestPki.signCsr(ca, bCsr.path("csrPem").asText(), 90);
        assertField(admin.put(keys(realm) + "/" + aKey + "/certificate",
                Map.of("certificateChainPem", TestPki.pem(bCert))), "certificateChainPem", "does not match", null);
        // The same key cannot be imported into a second realm.
        assertThat(admin.post(keys(realm) + "/import", Map.of("privateKeyPem", kpPem,
                "certificateChainPem", TestPki.pem(leaf))).status()).isEqualTo(201);
        assertField(admin.post(keys(other) + "/import", Map.of("privateKeyPem", kpPem,
                "certificateChainPem", TestPki.pem(leaf))), "privateKeyPem", "already stored", kpPem);

        // Cross-realm key ids are 404 on every key-id route.
        final String bKey = bCsr.path("key").path("keyId").asText();
        assertThat(admin.post(keys(realm) + "/" + bKey + "/activate?force=true", Map.of()).status()).isEqualTo(404);
        assertThat(admin.put(keys(realm) + "/" + bKey + "/certificate",
                Map.of("certificateChainPem", TestPki.pem(bCert))).status()).isEqualTo(404);
        assertThat(admin.get(keys(realm) + "/" + bKey + "/csr").status()).isEqualTo(404);
        assertThat(admin.delete(keys(realm) + "/" + bKey).status()).isEqualTo(404);
        assertThat(admin.get(keys(other)).json().toString()).contains(bKey); // untouched

        // State: activating an ACTIVE key, retiring it, attaching to a retired key.
        assertThat(admin.post(keys(realm) + "/" + aKey + "/activate?force=true", Map.of()).status()).isEqualTo(200);
        assertThat(admin.post(keys(realm) + "/" + aKey + "/activate?force=true", Map.of()).status()).isEqualTo(409);
        assertThat(admin.delete(keys(realm) + "/" + aKey).status()).isEqualTo(409);
        final String rotated = idWithStatus(admin.get(keys(realm)).json(), "ROTATED");
        assertThat(admin.delete(keys(realm) + "/" + rotated).status()).isEqualTo(204);
        assertThat(admin.put(keys(realm) + "/" + rotated + "/certificate",
                Map.of("certificateChainPem", TestPki.pem(leaf))).status()).isEqualTo(409);
    }

    // ------------------------------------------------------------------------------------------------ helpers

    private static String keys(final String realm) {
        return "/admin/realms/" + realm + "/keys";
    }

    private static String kid(final String jwt) throws Exception {
        return SignedJWT.parse(jwt).getHeader().getKeyID();
    }

    private static void assertNoSecrets(final String body, final String privatePem, final String privateB64) {
        assertThat(body).doesNotContain("PRIVATE KEY").doesNotContain(privateB64.substring(0, 40))
                .doesNotContain(privatePem.substring(30, 90));
    }

    private static void assertEveryJwkHasKidAlgUse(final JWKSet set) {
        for (final JWK jwk : set.getKeys()) {
            assertThat(jwk.getKeyID()).isNotBlank();
            assertThat(jwk.getAlgorithm()).isNotNull();
            assertThat(jwk.getKeyUse()).isEqualTo(com.nimbusds.jose.jwk.KeyUse.SIGNATURE);
        }
    }

    private static void assertField(final E2eHttp.Response r, final String field, final String contains,
                                    final String secret) {
        assertThat(r.status()).as(r.toString()).isEqualTo(400);
        final JsonNode errors = r.json().path("fieldErrors");
        assertThat(errors.has(field)).as(r.body()).isTrue();
        if (contains != null) {
            assertThat(errors.path(field).asText()).contains(contains);
        }
        if (secret != null) {
            assertThat(r.body()).doesNotContain(secret.substring(30, 90));
        }
    }

    private static String idWithStatus(final JsonNode list, final String status) {
        for (final JsonNode k : list) {
            if (status.equals(k.path("status").asText())) {
                return k.path("keyId").asText();
            }
        }
        throw new AssertionError("No " + status + " key in " + list);
    }

    private String metadata(final String realm) {
        final E2eHttp.Response r = newBrowser().get("/realms/" + realm + "/saml/idp/metadata");
        assertThat(r.status()).as(r.toString()).isEqualTo(200);
        return r.body();
    }

    /** The certificates of the {@code use="signing"} KeyDescriptors, in order. */
    private List<String> metadataSigningCerts(final String realm) {
        final String xml = metadata(realm);
        final List<String> out = new ArrayList<>();
        final java.util.regex.Matcher m = java.util.regex.Pattern.compile(
                "<md:KeyDescriptor use=\"signing\">.*?<ds:X509Certificate>(.*?)</ds:X509Certificate>").matcher(xml);
        while (m.find()) {
            out.add(m.group(1));
        }
        return out;
    }

    /** Issues a SAML Response with the realm's live credential and validates it (OpenSAML) against {@code certPem}. */
    private String assertSamlSignedWith(final String realm, final String certPem) {
        final SamlIdpConfig idp = context.getBean(RealmSamlCredentialSource.class).forRealm(realm);
        final String response = new SamlAssertionIssuer().issueResponse(idp, "https://sp.example/" + realm,
                "https://sp.example/acs", "ada@corp", Map.of("mail", "ada@corp"),
                "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport", "_req-" + realm,
                SamlSpOptions.defaults());
        final SamlProviderConfig sp = new SamlProviderConfig("helix-idp", "Helix", idp.idpEntityId() + "/sso",
                idp.idpEntityId(), "https://sp.example/" + realm, "https://sp.example/acs",
                certPem == null ? idp.signingCertificate() : certPem, "mail",
                "givenName", "sn");
        final SamlAssertionValidator.ValidatedAssertion validated =
                new OpenSamlAssertionValidator(new InMemorySamlAssertionReplayCache()).validate(sp, response, "relay");
        assertThat(validated.nameId()).isEqualTo("ada@corp");
        return new String(Base64.getDecoder().decode(response), StandardCharsets.UTF_8);
    }
}
