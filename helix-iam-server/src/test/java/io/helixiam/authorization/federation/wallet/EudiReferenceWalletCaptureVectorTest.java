/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.wallet;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.util.Base64URL;
import io.helixiam.authorization.federation.wallet.mdoc.MdocPresentationVerifier;
import io.helixiam.authorization.federation.wallet.mdoc.SessionTranscripts;
import io.helixiam.authorization.federation.wallet.sdjwt.SdJwtVcPresentationVerifier;
import io.helixiam.authorization.federation.wallet.status.StatusEvaluator;
import io.helixiam.authorization.federation.wallet.status.StatusPolicy;
import io.helixiam.authorization.federation.wallet.status.StatusReference;
import io.helixiam.authorization.federation.wallet.trust.IssuerTrustValidator;
import io.helixiam.authorization.federation.wallet.trust.TrustAnchors;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * Third-party presentations, verified offline: what the EU Digital Identity Wallet reference app (2026.10.43-Demo)
 * posted to this verifier on 2026-10-15, with PIDs issued by the EU reference PID issuer (issuer.eudiw.dev). Each
 * directory under {@code wallet/vectors/eudi-reference-wallet/} holds the signed request object the wallet fetched, the
 * {@code direct_post.jwt} response it posted, and the verifier's per-transaction decryption key (captured with a
 * test-only database trigger, never by product code). Provenance and licence: {@code wallet/vectors/SOURCES.md}.
 *
 * <p>For each capture the test runs the production pipeline: {@link VpResponseDecryptor} decrypts the JWE, then
 * {@link MdocPresentationVerifier} (IssuerAuth chain to the reference PID CA, MSO digests, and DeviceAuth over the
 * OpenID4VP SessionTranscript built from {@code client_id}, {@code nonce}, the JWK thumbprint and {@code response_uri})
 * or {@link SdJwtVcPresentationVerifier} (issuer signature and chain, disclosures, KB-JWT {@code aud}, {@code nonce},
 * {@code iat} and {@code sd_hash}). Time is the capture time. Issuer-certificate revocation and the status-list fetch
 * are network checks and are off here; the live runs did both (see docs/compliance/eudi-reference-wallet/).
 */
class EudiReferenceWalletCaptureVectorTest {

    private static final String BASE = "/wallet/vectors/eudi-reference-wallet/";
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final Set<EncryptionMethod> ENC = Set.of(EncryptionMethod.A128GCM, EncryptionMethod.A256GCM);
    private static final String PID_DOCTYPE = "eu.europa.ec.eudi.pid.1";
    private static final Set<String> PID_VCTS = Set.of("urn:eudi:pid:1");

    private final List<StatusReference> statusRefs = new ArrayList<>();
    private final StatusEvaluator status = (ref, anchors, issuer) -> {
        statusRefs.add(ref);
        return StatusEvaluator.VALID;
    };

    // --------------------------------------------------------------------------------------------- fixtures

    private record Capture(String dir, JsonNode meta, String requestObject, String jwe, ECKey key,
                           JsonNode decrypted) {
        String clientId() { return meta.get("clientId").asText(); }
        String nonce() { return meta.get("nonce").asText(); }
        String responseUri() { return meta.get("responseUri").asText(); }
        Instant capturedAt() { return Instant.parse(meta.get("capturedAt").asText()); }
    }

    private static String text(final String path) throws IOException {
        try (InputStream in = EudiReferenceWalletCaptureVectorTest.class.getResourceAsStream(BASE + path)) {
            assertThat(in).as(path).isNotNull();
            return new String(in.readAllBytes(), StandardCharsets.US_ASCII).trim();
        }
    }

    private static Capture load(final String dir) throws Exception {
        return new Capture(dir, JSON.readTree(text(dir + "/capture.json")), text(dir + "/request-object.jwt"),
                text(dir + "/response.jwe"), ECKey.parse(text(dir + "/verifier-ephemeral-key.jwk.json")),
                JSON.readTree(text(dir + "/decrypted-response.json")));
    }

    private static TrustAnchors referencePidCa() throws IOException {
        return TrustAnchors.fromPem(text("pid-issuer-ca-ut-02.crt"), null, TrustAnchors.RevocationMode.OFF);
    }

    private static VerificationContext context(final Capture c, final String clientId, final String nonce,
            final byte[] thumbprint, final String responseUri) throws IOException {
        return new VerificationContext(clientId, nonce, responseUri, thumbprint, c.capturedAt(), Duration.ofSeconds(60),
                referencePidCa(), new StatusPolicy(false, StatusPolicy.OnUnavailable.FAIL_CLOSED,
                        Duration.ofSeconds(900), List.of()), PID_VCTS, PID_DOCTYPE, false);
    }

    private static VerificationContext context(final Capture c) throws Exception {
        return context(c, c.clientId(), c.nonce(), c.key().computeThumbprint().decode(), c.responseUri());
    }

    private static String presentation(final Capture c) {
        final DecryptedResponse response = new VpResponseDecryptor().decrypt(c.jwe(), c.key(), ENC);
        final JsonNode entries = response.vpToken().get(c.meta().get("dcqlQueryId").asText());
        assertThat(entries).as("vp_token entry").isNotNull();
        assertThat(entries.size()).isEqualTo(1);
        return entries.get(0).asText();
    }

    private static X509Certificate certificate(final byte[] der) throws Exception {
        return (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(der));
    }

    // ------------------------------------------------------------------------------------- request object

    @ParameterizedTest
    @ValueSource(strings = {"mdoc-same-device", "mdoc-cross-device", "sd-jwt-same-device", "sd-jwt-cross-device"})
    void requestObjectIsSignedByTheRegisteredAccessCertificateAndMatchesTheCapture(final String dir) throws Exception {
        final Capture c = load(dir);
        final JWSObject request = JWSObject.parse(c.requestObject());
        final X509Certificate leaf = certificate(request.getHeader().getX509CertChain().get(0).decode());

        assertThat(request.verify(new ECDSAVerifier((ECPublicKey) leaf.getPublicKey()))).isTrue();
        assertThat(leaf.getIssuerX500Principal().getName()).contains("CN=WRPAC Issuer CA 01");
        leaf.verify(certificate(Base64.getMimeDecoder().decode(text("wrpac-issuer-ca-ut-01.crt")
                .replaceAll("-----[A-Z ]+-----", ""))).getPublicKey());
        final String x509Hash = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(MessageDigest.getInstance("SHA-256").digest(leaf.getEncoded()));
        assertThat(c.clientId()).isEqualTo("x509_hash:" + x509Hash);

        final JsonNode claims = JSON.readTree(request.getPayload().toString());
        assertThat(claims.get("client_id").asText()).isEqualTo(c.clientId());
        assertThat(claims.get("nonce").asText()).isEqualTo(c.nonce());
        assertThat(claims.get("response_uri").asText()).isEqualTo(c.responseUri());
        assertThat(claims.get("response_mode").asText()).isEqualTo("direct_post.jwt");
        final ECKey advertised = ECKey.parse(claims.get("client_metadata").get("jwks").get("keys").get(0).toString());
        assertThat(advertised.toPublicJWK()).isEqualTo(c.key().toPublicJWK());
        assertThat(c.key().computeThumbprint())
                .isEqualTo(new Base64URL(c.meta().get("encryptionJwkThumbprint").asText()));
    }

    @ParameterizedTest
    @ValueSource(strings = {"mdoc-same-device", "mdoc-cross-device", "sd-jwt-same-device", "sd-jwt-cross-device"})
    void responseDecryptsToTheRecordedPayload(final String dir) throws Exception {
        final Capture c = load(dir);
        final DecryptedResponse response = new VpResponseDecryptor().decrypt(c.jwe(), c.key(), ENC);
        assertThat(response.vpToken()).isEqualTo(c.decrypted().get("vp_token"));
        assertThat(response.state()).isEqualTo(c.decrypted().get("state").asText());
    }

    // ----------------------------------------------------------------------------------------------- mdoc

    @ParameterizedTest
    @ValueSource(strings = {"mdoc-same-device", "mdoc-cross-device"})
    void mdocDeviceAuthAndIssuerAuthVerifyOffline(final String dir) throws Exception {
        final Capture c = load(dir);
        assertThat(HexFormat.of().formatHex(SessionTranscripts.openId4VpRedirect(c.clientId(), c.nonce(),
                c.key().computeThumbprint().decode(), c.responseUri())))
                .isEqualTo(c.meta().get("sessionTranscriptHex").asText());

        final VerifiedPresentation verified = new MdocPresentationVerifier(new IssuerTrustValidator(), status)
                .verify(presentation(c), context(c));

        assertThat(verified.format()).isEqualTo("mso_mdoc");
        assertThat(verified.credentialType()).isEqualTo(PID_DOCTYPE);
        assertThat(verified.issuerSubjectDn()).contains("CN=PID DS - 003");
        assertThat(verified.claims()).containsOnlyKeys(PID_DOCTYPE);
        @SuppressWarnings("unchecked")
        final java.util.Map<String, Object> pid = (java.util.Map<String, Object>) verified.claims().get(PID_DOCTYPE);
        assertThat(pid).containsEntry("given_name", "Refw").containsEntry("family_name", "Tester")
                .containsEntry("birth_date", "1990-01-01")
                .containsEntry("personal_administrative_number", "REFW-TEST-0001")
                .containsEntry("issuing_country", "FC");
        final JsonNode ref = c.meta().get("statusListReference");
        assertThat(statusRefs).containsExactly(new StatusReference(ref.get("idx").asInt(), ref.get("uri").asText()));
    }

    @ParameterizedTest
    @ValueSource(strings = {"mdoc-same-device", "mdoc-cross-device"})
    void mdocDeviceAuthFailsForAnyOtherSessionTranscript(final String dir) throws Exception {
        final Capture c = load(dir);
        final MdocPresentationVerifier verifier = new MdocPresentationVerifier(new IssuerTrustValidator(), status);
        final String presentation = presentation(c);
        final byte[] thumb = c.key().computeThumbprint().decode();
        final byte[] otherThumb = thumb.clone();
        otherThumb[0] ^= 1;

        for (final VerificationContext wrong : List.of(
                context(c, c.clientId(), c.nonce() + "x", thumb, c.responseUri()),
                context(c, c.clientId() + "x", c.nonce(), thumb, c.responseUri()),
                context(c, c.clientId(), c.nonce(), otherThumb, c.responseUri()),
                context(c, c.clientId(), c.nonce(), null, c.responseUri()),
                context(c, c.clientId(), c.nonce(), thumb, c.responseUri() + "x"))) {
            assertThatThrownBy(() -> verifier.verify(presentation, wrong))
                    .isInstanceOfSatisfying(WalletVerificationException.class,
                            e -> assertThat(e.code()).isEqualTo(WalletErrorCode.HOLDER_BINDING_INVALID));
        }
    }

    @Test
    void mdocIssuerAuthMustChainToTheConfiguredAnchor() throws Exception {
        final Capture c = load("mdoc-same-device");
        final VerificationContext ctx = context(c);
        final VerificationContext otherAnchor = new VerificationContext(ctx.clientId(), ctx.nonce(),
                ctx.responseUri(), ctx.encryptionJwkThumbprint(), ctx.now(), ctx.clockSkew(),
                TrustAnchors.fromPem(text("wrpac-issuer-ca-ut-01.crt"), null, TrustAnchors.RevocationMode.OFF),
                ctx.statusPolicy(), ctx.acceptedVcts(), ctx.acceptedDoctype(), false);
        assertThatThrownBy(() -> new MdocPresentationVerifier(new IssuerTrustValidator(), status)
                .verify(presentation(c), otherAnchor))
                .isInstanceOfSatisfying(WalletVerificationException.class,
                        e -> assertThat(e.code()).isEqualTo(WalletErrorCode.ISSUER_UNTRUSTED));
    }

    // --------------------------------------------------------------------------------------------- SD-JWT

    @ParameterizedTest
    @ValueSource(strings = {"sd-jwt-same-device", "sd-jwt-cross-device"})
    void sdJwtIssuerSignatureAndKeyBindingVerifyOffline(final String dir) throws Exception {
        final Capture c = load(dir);
        final VerifiedPresentation verified = new SdJwtVcPresentationVerifier(new IssuerTrustValidator(), status)
                .verify(presentation(c), context(c));

        assertThat(verified.format()).isEqualTo("dc+sd-jwt");
        assertThat(verified.credentialType()).isEqualTo("urn:eudi:pid:1");
        assertThat(verified.issuerSubjectDn()).contains("CN=PID DS - 003");
        assertThat(verified.claims()).containsEntry("given_name", "Refw").containsEntry("family_name", "Tester")
                .containsEntry("birthdate", "1990-01-01")
                .containsEntry("personal_administrative_number", "REFW-TEST-0001")
                .containsEntry("issuing_country", "FC");
        final JsonNode ref = c.meta().get("statusListReference");
        assertThat(statusRefs).containsExactly(new StatusReference(ref.get("idx").asInt(), ref.get("uri").asText()));
    }

    @ParameterizedTest
    @ValueSource(strings = {"sd-jwt-same-device", "sd-jwt-cross-device"})
    void sdJwtKeyBindingIsBoundToThisRequest(final String dir) throws Exception {
        final Capture c = load(dir);
        final SdJwtVcPresentationVerifier verifier = new SdJwtVcPresentationVerifier(new IssuerTrustValidator(), status);
        final String presentation = presentation(c);
        final byte[] thumb = c.key().computeThumbprint().decode();

        assertThatThrownBy(() -> verifier.verify(presentation,
                context(c, c.clientId(), c.nonce() + "x", thumb, c.responseUri())))
                .isInstanceOfSatisfying(WalletVerificationException.class,
                        e -> assertThat(e.code()).isEqualTo(WalletErrorCode.NONCE_MISMATCH));
        assertThatThrownBy(() -> verifier.verify(presentation,
                context(c, c.clientId() + "x", c.nonce(), thumb, c.responseUri())))
                .isInstanceOfSatisfying(WalletVerificationException.class,
                        e -> assertThat(e.code()).isEqualTo(WalletErrorCode.AUDIENCE_MISMATCH));

        final VerificationContext ctx = context(c);
        final VerificationContext late = new VerificationContext(ctx.clientId(), ctx.nonce(), ctx.responseUri(),
                ctx.encryptionJwkThumbprint(), ctx.now().plus(Duration.ofMinutes(10)), ctx.clockSkew(),
                ctx.anchors(), ctx.statusPolicy(), ctx.acceptedVcts(), ctx.acceptedDoctype(), false);
        assertThatThrownBy(() -> verifier.verify(presentation, late))
                .isInstanceOfSatisfying(WalletVerificationException.class, e -> {
                    assertThat(e.code()).isEqualTo(WalletErrorCode.HOLDER_BINDING_INVALID);
                    assertThat(e.getMessage()).contains("iat is outside the window");
                });
    }
}
