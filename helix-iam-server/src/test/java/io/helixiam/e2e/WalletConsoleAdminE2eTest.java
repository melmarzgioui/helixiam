/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.e2e;

import com.fasterxml.jackson.databind.JsonNode;
import io.helixiam.authorization.federation.wallet.testwallet.TestPki;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.openssl.jcajce.JcaPKCS8Generator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.StringWriter;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Task 24: the admin endpoints behind the console's "EUDI Wallet (OpenID4VP)" provider screen, over real HTTP with
 * the console's session + CSRF: the verifier access-key import and listing ({@code /verifier-keys}), the wallet
 * metadata (PID claim catalogue, dev profile) and the certificate preview of a trust-anchor bundle. Every write
 * refusal is a {@code 400 {message, fieldErrors}} on the form field, never a 500; the private key never comes back;
 * all of it needs {@code manage-identity-providers}.
 */
class WalletConsoleAdminE2eTest extends AbstractE2eTest {

    private String realm;
    private E2eAdminSession admin;
    private TestPki pki;

    @BeforeEach
    void setUp() {
        realm = E2eSeed.unique("walletui");
        seed().realm(realm);
        admin = adminSession();
        pki = TestPki.create("Console Test");
    }

    private String keys() {
        return "/admin/realms/" + realm + "/verifier-keys";
    }

    // ---------------------------------------------------------------- verifier keys

    @Test
    void importReturnsTheKeyRefAndLeafSummary_neverTheKey_andTheListShowsIt() throws Exception {
        final TestPki.Leaf leaf = pki.issueLeaf(TestPki.LeafSpec.defaults().withSubject("CN=verifier.example,O=Acme")
                .withDnsNames("verifier.example", "login.example"));
        final String keyPem = pem(leaf.privateKey());
        final E2eHttp.Response created = admin.post(keys(), Map.of("name", "access-2026",
                "privateKeyPem", keyPem, "certificateChainPem", chainPem(leaf) + pki.rootPem()));

        assertThat(created.status()).as(created.toString()).isEqualTo(201);
        assertThat(created.body()).doesNotContain("PRIVATE KEY").doesNotContain(strip(keyPem));
        final JsonNode body = created.json();
        assertThat(body.path("keyRef").asText()).isEqualTo("software:" + realm + "/access-2026");
        assertThat(body.path("name").asText()).isEqualTo("access-2026");
        assertThat(body.path("algorithm").asText()).isEqualTo("ES256");
        assertThat(body.path("chainLength").asInt()).isEqualTo(2); // leaf + intermediate; the root is dropped
        final JsonNode cert = body.path("certificate");
        assertThat(cert.path("subject").asText()).contains("CN=verifier.example");
        assertThat(cert.path("issuer").asText()).contains("Console Test");
        assertThat(cert.path("notAfter").asText()).isNotBlank();
        assertThat(cert.path("ca").asBoolean()).isFalse();
        assertThat(texts(cert.path("dnsNames"))).containsExactlyInAnyOrder("verifier.example", "login.example");

        final E2eHttp.Response list = admin.get(keys());
        assertThat(list.status()).as(list.toString()).isEqualTo(200);
        assertThat(list.body()).doesNotContain("PRIVATE KEY").doesNotContain(strip(keyPem));
        assertThat(list.json()).hasSize(1);
        assertThat(list.json().get(0).path("keyRef").asText()).isEqualTo("software:" + realm + "/access-2026");
        assertThat(list.json().get(0).path("createdAt").asText()).isNotBlank();
        assertThat(list.json().get(0).path("certificate").path("subject").asText()).contains("CN=verifier.example");

        // Another realm's admin listing does not show it.
        final String other = E2eSeed.unique("walletui-other");
        seed().realm(other);
        assertThat(admin.get("/admin/realms/" + other + "/verifier-keys").json()).isEmpty();
    }

    @Test
    void importRefusals_are400WithTheFormField_neverA500() throws Exception {
        final TestPki.Leaf leaf = pki.issueLeaf(TestPki.LeafSpec.defaults());
        final String key = pem(leaf.privateKey());
        final String chain = chainPem(leaf);

        expectField(Map.of("name", "", "privateKeyPem", key, "certificateChainPem", chain), "name");
        expectField(Map.of("name", "bad/name", "privateKeyPem", key, "certificateChainPem", chain), "name");
        expectField(Map.of("name", "k", "privateKeyPem", "", "certificateChainPem", chain), "privateKeyPem");
        expectField(Map.of("name", "k", "privateKeyPem", "not a pem", "certificateChainPem", chain), "privateKeyPem");
        expectField(Map.of("name", "k", "privateKeyPem", key, "certificateChainPem", "garbage"), "certificateChainPem");

        // Self-signed (HAIP) and the wrong curve.
        final TestPki.Leaf self = TestPki.selfSignedLeaf("CN=self");
        expectField(Map.of("name", "self", "privateKeyPem", pem(self.privateKey()),
                "certificateChainPem", TestPki.pem(self.certificate())), "certificateChainPem");
        final KeyPairGenerator gen = KeyPairGenerator.getInstance("EC",
                new org.bouncycastle.jce.provider.BouncyCastleProvider());
        gen.initialize(new ECGenParameterSpec("secp256k1"));
        expectField(Map.of("name", "k1", "privateKeyPem", pem(gen.generateKeyPair().getPrivate()),
                "certificateChainPem", chain), "privateKeyPem");

        // A taken name.
        assertThat(admin.post(keys(), Map.of("name", "dup", "privateKeyPem", key, "certificateChainPem", chain))
                .status()).isEqualTo(201);
        expectField(Map.of("name", "dup", "privateKeyPem", key, "certificateChainPem", chain), "name");
        assertThat(admin.get(keys()).json()).hasSize(1);
    }

    @Test
    void verifierKeysAndWalletHelpers_needManageIdentityProviders_andCsrf() throws Exception {
        final TestPki.Leaf leaf = pki.issueLeaf(TestPki.LeafSpec.defaults());
        final Map<String, String> body = Map.of("name", "rbac", "privateKeyPem", pem(leaf.privateKey()),
                "certificateChainPem", chainPem(leaf));

        final E2eAdminSession realmOnly = scopedAdmin("manage-realm");
        assertThat(realmOnly.get(keys()).status()).isEqualTo(403);
        assertThat(realmOnly.post(keys(), body).status()).isEqualTo(403);
        assertThat(realmOnly.get("/admin/realms/" + realm + "/wallet/metadata").status()).isEqualTo(403);
        assertThat(realmOnly.post("/admin/realms/" + realm + "/wallet/certificates/preview",
                Map.of("pem", pki.rootPem())).status()).isEqualTo(403);

        // A write without the X-XSRF-TOKEN header is refused, even for a full admin.
        assertThat(admin.http().sendJson("POST", keys(), body).status()).isEqualTo(403);
        assertThat(admin.get(keys()).json()).isEmpty();

        final E2eAdminSession idpAdmin = scopedAdmin("manage-identity-providers");
        final E2eHttp.Response created = idpAdmin.post(keys(), body);
        assertThat(created.status()).as(created.toString()).isEqualTo(201);
        assertThat(idpAdmin.get(keys()).json()).hasSize(1);
        assertThat(idpAdmin.get("/admin/realms/" + realm + "/wallet/metadata").status()).isEqualTo(200);
    }

    // ---------------------------------------------------------------- wallet metadata + certificate preview

    @Test
    void metadataListsThePidClaimCatalogue_andTheProfile() {
        final E2eHttp.Response response = admin.get("/admin/realms/" + realm + "/wallet/metadata");
        assertThat(response.status()).as(response.toString()).isEqualTo(200);
        final JsonNode meta = response.json();
        final List<String> names = new ArrayList<>();
        meta.path("pidClaims").forEach(c -> names.add(c.path("name").asText()));
        assertThat(names).contains("given_name", "family_name", "birthdate", "place_of_birth",
                "personal_administrative_number", "address.house_number");
        meta.path("pidClaims").forEach(c -> {
            if ("address.house_number".equals(c.path("name").asText())) {
                assertThat(c.path("mdoc").asBoolean()).as("no mdoc element").isFalse();
            }
            if ("given_name".equals(c.path("name").asText())) {
                assertThat(c.path("mdoc").asBoolean()).isTrue();
                assertThat(c.path("releasable").asBoolean()).as("verify-only may release it").isTrue();
            }
            if ("personal_administrative_number".equals(c.path("name").asText())) {
                assertThat(c.path("releasable").asBoolean()).as("a binding claim, never released").isFalse();
            }
        });
        assertThat(texts(meta.path("defaultRequestedClaims"))).containsExactly("given_name", "family_name", "birthdate");
        assertThat(texts(meta.path("credentialFormats"))).containsExactly("dc+sd-jwt", "mso_mdoc");
        assertThat(meta.path("devProfile").isBoolean()).isTrue();
    }

    @Test
    void certificatePreview_parsesABundle_andFlagsWhatCannotBeATrustAnchor() {
        final TestPki.Leaf leaf = pki.issueLeaf(TestPki.LeafSpec.defaults().withDnsNames("rp.example"));
        final String bundle = pki.rootPem() + TestPki.pem(leaf.certificate());
        final E2eHttp.Response response = admin.post("/admin/realms/" + realm + "/wallet/certificates/preview",
                Map.of("pem", bundle));
        assertThat(response.status()).as(response.toString()).isEqualTo(200);
        final JsonNode certs = response.json().path("certificates");
        assertThat(certs).hasSize(2);
        final JsonNode root = certs.get(0);
        assertThat(root.path("subject").asText()).contains("Console Test");
        assertThat(root.path("ca").asBoolean()).isTrue();
        assertThat(root.path("selfSigned").asBoolean()).isTrue();
        assertThat(root.path("notAfter").asText()).isNotBlank();
        assertThat(root.path("trustAnchorProblem").isNull()).isTrue();
        final JsonNode leafView = certs.get(1);
        assertThat(leafView.path("ca").asBoolean()).isFalse();
        assertThat(leafView.path("trustAnchorProblem").asText()).contains("not a CA certificate");
        assertThat(texts(leafView.path("dnsNames"))).containsExactly("rp.example");

        final E2eHttp.Response bad = admin.post("/admin/realms/" + realm + "/wallet/certificates/preview",
                Map.of("pem", "-----BEGIN CERTIFICATE-----\nnope\n-----END CERTIFICATE-----"));
        assertThat(bad.status()).as(bad.toString()).isEqualTo(400);
        assertThat(bad.json().path("fieldErrors").has("pem")).isTrue();
        final E2eHttp.Response empty = admin.post("/admin/realms/" + realm + "/wallet/certificates/preview",
                Map.of("pem", ""));
        assertThat(empty.status()).as(empty.toString()).isEqualTo(400);
        assertThat(empty.json().path("fieldErrors").has("pem")).isTrue();
    }

    /** Security review: trusted_authorities On with an anchor that has no SubjectKeyIdentifier is a 400 on the field. */
    @Test
    void trustedAuthoritiesOn_withAnAnchorWithoutSubjectKeyIdentifier_is400OnTheField() throws Exception {
        final TestPki.Leaf leaf = pki.issueLeaf(TestPki.LeafSpec.defaults().withSubject("CN=verifier.example"));
        final E2eHttp.Response key = admin.post(keys(), Map.of("name", "access-ta",
                "privateKeyPem", pem(leaf.privateKey()), "certificateChainPem", chainPem(leaf)));
        assertThat(key.status()).as(key.toString()).isEqualTo(201);
        final String anchors = TestPki.create("TA Issuer").rootPem()
                + TestPki.pem(TestPki.caCertificate(TestPki.KeyType.EC_P256, null));
        final Map<String, Object> config = new java.util.LinkedHashMap<>();
        config.put("accessKeyRef", key.json().path("keyRef").asText());
        config.put("trustAnchors", anchors);
        config.put("revocationChecking", "OFF");
        config.put("dcql.trustedAuthorities", "true");
        final Map<String, Object> body = new java.util.LinkedHashMap<>();
        body.put("alias", "eudi-ta");
        body.put("protocol", "eudi-wallet");
        body.put("displayName", "EU Wallet");
        body.put("enabled", true);
        body.put("config", config);

        final E2eHttp.Response refused = admin.post("/admin/realms/" + realm + "/identity-providers", body);
        assertThat(refused.status()).as(refused.toString()).isEqualTo(400);
        assertThat(refused.json().path("fieldErrors").has("config.dcql.trustedAuthorities")).as(refused.toString())
                .isTrue();

        config.put("dcql.trustedAuthorities", "false");
        final E2eHttp.Response created = admin.post("/admin/realms/" + realm + "/identity-providers", body);
        assertThat(created.status()).as(created.toString()).isEqualTo(201);
    }

    // ---------------------------------------------------------------- helpers

    private void expectField(final Map<String, String> body, final String field) {
        final E2eHttp.Response r = admin.post(keys(), body);
        assertThat(r.status()).as(r.toString()).isEqualTo(400);
        assertThat(r.json().path("fieldErrors").has(field)).as(r.toString()).isTrue();
        assertThat(r.json().path("message").asText()).isNotBlank();
        assertThat(r.body()).doesNotContain("-----BEGIN"); // never echoes PEM input
    }

    private static List<String> texts(final JsonNode array) {
        final List<String> out = new ArrayList<>();
        array.forEach(n -> out.add(n.asText()));
        return out;
    }

    private static String chainPem(final TestPki.Leaf leaf) {
        final StringBuilder sb = new StringBuilder();
        leaf.chain().forEach(c -> sb.append(TestPki.pem(c)));
        return sb.toString();
    }

    private static String pem(final PrivateKey key) throws IOException {
        final StringWriter out = new StringWriter();
        try (JcaPEMWriter w = new JcaPEMWriter(out)) {
            w.writeObject(new JcaPKCS8Generator(key, null));
        }
        return out.toString();
    }

    /** The base64 body of a PEM block, to assert it never comes back in any form. */
    private static String strip(final String pem) {
        return pem.replaceAll("-----[A-Z ]+-----", "").replaceAll("\\s", "").substring(0, 40);
    }

    /** A user of {@link #realm} whose only admin permission is {@code permission}, logged in. */
    private E2eAdminSession scopedAdmin(final String permission) {
        final String roleName = E2eSeed.unique("wallet-" + permission);
        final E2eHttp.Response role = admin.post("/admin/realms/" + realm + "/roles", Map.of("name", roleName));
        assertThat(role.status()).as(role.toString()).isEqualTo(201);
        String roleId = role.json().path("roleId").asText();
        if (roleId.isBlank()) {
            for (final JsonNode r : admin.get("/admin/realms/" + realm + "/roles").json()) {
                if (roleName.equals(r.path("name").asText())) {
                    roleId = r.path("roleId").asText();
                }
            }
        }
        assertThat(admin.put("/admin/realms/" + realm + "/admin-roles/" + roleId,
                Map.of("permissions", List.of(permission))).status()).isEqualTo(200);
        final E2eSeed.SeededUser user = seed().user(realm, E2eSeed.unique("scoped"), "Sc0ped-Admin-Passw0rd!");
        assertThat(admin.post("/admin/realms/" + realm + "/users/" + user.userId() + "/roles", Map.of("roleId", roleId))
                .status()).isEqualTo(204);
        return E2eAdminSession.login(newBrowser(), realm, user.username(), user.password());
    }
}
