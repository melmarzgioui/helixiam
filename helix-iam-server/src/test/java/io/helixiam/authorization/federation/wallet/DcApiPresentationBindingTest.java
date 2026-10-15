/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.wallet;

import io.helixiam.authorization.federation.wallet.mdoc.MdocPresentationVerifier;
import io.helixiam.authorization.federation.wallet.sdjwt.SdJwtVcPresentationVerifier;
import io.helixiam.authorization.federation.wallet.status.StatusEvaluator;
import io.helixiam.authorization.federation.wallet.status.StatusPolicy;
import io.helixiam.authorization.federation.wallet.testwallet.TestWallet;
import io.helixiam.authorization.federation.wallet.trust.IssuerTrustValidator;
import io.helixiam.authorization.federation.wallet.trust.TrustAnchors;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * OpenID4VP 1.0 Appendix A.4 / B.2.6.2: over the Digital Credentials API a presentation is bound to the web origin,
 * not the client_id. SD-JWT: the KB-JWT {@code aud} is {@code origin:<Origin>}; mdoc: DeviceAuth is over the
 * {@code OpenID4VPDCAPIHandover} SessionTranscript (built here with Jackson, independently of production code). The
 * verifier accepts only its own expected origins, and a redirect-bound presentation is never accepted in a DC API
 * context, nor a DC API one in a redirect context.
 */
class DcApiPresentationBindingTest {

    private static final String CLIENT_ID = "x509_hash:Uvo3HtuIxuhC92rShpgqcT3YXwrqRxWEviRiA0OZszk";
    private static final String NONCE = "exc7gBkxjx1rdc9udRrveKvSsJIq80avlXeLHhGwqtA";
    private static final String ORIGIN = "https://login.example.eu";
    private static final String OTHER_ORIGIN = "https://id.example.eu";
    private static final String EVIL_ORIGIN = "https://evil.example.com";
    private static final byte[] THUMBPRINT = new byte[32];
    private static final StatusEvaluator VALID = (ref, a, issuer) -> StatusEvaluator.VALID;

    private static TestWallet wallet;
    private static TrustAnchors anchors;

    @BeforeAll
    static void setUp() {
        wallet = TestWallet.create();
        anchors = wallet.pki().trustAnchors(TrustAnchors.RevocationMode.OFF);
        Arrays.fill(THUMBPRINT, (byte) 9);
    }

    private static VerificationContext redirect() {
        return new VerificationContext(CLIENT_ID, NONCE, "https://login.example.eu/response", THUMBPRINT, Instant.now(),
                Duration.ofSeconds(60), anchors, new StatusPolicy(false, StatusPolicy.OnUnavailable.FAIL_CLOSED,
                Duration.ofSeconds(900), List.of()), Set.of(TestWallet.PID_VCT), TestWallet.MDOC_PID_DOCTYPE, false);
    }

    private static VerificationContext dcApi(final String... origins) {
        return redirect().forDcApi(List.of(origins));
    }

    private static Map<String, Object> sdJwtClaims() {
        final Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("given_name", "Erika");
        claims.put("family_name", "Mustermann");
        claims.put("birthdate", "1964-08-12");
        return claims;
    }

    private static String sdJwt(final String aud) {
        final Instant now = Instant.now();
        final TestWallet.SdJwtCredential pid = wallet.sdJwtPid(sdJwtClaims(), now.minusSeconds(3600),
                now.plusSeconds(3600), Optional.empty());
        return wallet.present(pid, sdJwtClaims().keySet(), aud, NONCE);
    }

    private static SdJwtVcPresentationVerifier sdJwtVerifier() {
        return new SdJwtVcPresentationVerifier(new IssuerTrustValidator(), VALID);
    }

    private static MdocPresentationVerifier mdocVerifier() {
        return new MdocPresentationVerifier(new IssuerTrustValidator(), VALID);
    }

    /** OpenID4VPDCAPIHandover transcript, written with Jackson. */
    private static byte[] dcApiTranscript(final String origin, final byte[] thumbprint) {
        final byte[] info = TestWallet.cbor(Arrays.asList(origin, NONCE, thumbprint));
        return TestWallet.cbor(Arrays.asList(null, null,
                List.of("OpenID4VPDCAPIHandover", TestWallet.sha("SHA-256", info))));
    }

    private static byte[] redirectTranscript() {
        final byte[] info = TestWallet.cbor(Arrays.asList(CLIENT_ID, NONCE, THUMBPRINT,
                "https://login.example.eu/response"));
        return TestWallet.cbor(Arrays.asList(null, null,
                List.of("OpenID4VPHandover", TestWallet.sha("SHA-256", info))));
    }

    private static String mdoc(final byte[] transcript) {
        final Instant now = Instant.now();
        final Map<String, Object> claims = Map.of("given_name", "Erika", "family_name", "Mustermann");
        final TestWallet.MdocCredential credential = wallet.mdocPid(claims, now.minusSeconds(3600),
                now.minusSeconds(3600), now.plusSeconds(3600), Optional.empty());
        return TestWallet.b64url(TestWallet.mdocDeviceResponse(credential, claims.keySet(), transcript));
    }

    private static void refused(final Runnable verify, final WalletErrorCode code) {
        assertThatThrownBy(verify::run).isInstanceOfSatisfying(WalletVerificationException.class,
                e -> assertThat(e.code()).isEqualTo(code));
    }

    // ------------------------------------------------------------------ SD-JWT VC

    @Test
    void sdJwt_audOriginPrefixedExpectedOrigin_isAccepted() {
        assertThat(sdJwtVerifier().verify(sdJwt("origin:" + ORIGIN), dcApi(ORIGIN)).claims())
                .containsEntry("given_name", "Erika");
        assertThat(sdJwtVerifier().verify(sdJwt("origin:" + OTHER_ORIGIN), dcApi(ORIGIN, OTHER_ORIGIN)).claims())
                .containsEntry("family_name", "Mustermann");
    }

    @Test
    void sdJwt_anotherOrigin_isRefused() {
        refused(() -> sdJwtVerifier().verify(sdJwt("origin:" + EVIL_ORIGIN), dcApi(ORIGIN)),
                WalletErrorCode.AUDIENCE_MISMATCH);
    }

    @Test
    void sdJwt_bareOriginWithoutPrefix_isRefused() {
        refused(() -> sdJwtVerifier().verify(sdJwt(ORIGIN), dcApi(ORIGIN)), WalletErrorCode.AUDIENCE_MISMATCH);
    }

    @Test
    void sdJwt_boundToTheClientId_isRefusedOverTheDcApi() {
        // A.4: "the Client Identifier is not used as the audience for the response", even for signed requests.
        refused(() -> sdJwtVerifier().verify(sdJwt(CLIENT_ID), dcApi(ORIGIN)), WalletErrorCode.AUDIENCE_MISMATCH);
    }

    @Test
    void sdJwt_boundToAnOrigin_isRefusedInTheRedirectFlow() {
        refused(() -> sdJwtVerifier().verify(sdJwt("origin:" + ORIGIN), redirect()),
                WalletErrorCode.AUDIENCE_MISMATCH);
    }

    // ------------------------------------------------------------------ mdoc

    @Test
    void mdoc_deviceAuthOverTheDcApiTranscript_isAccepted() {
        assertThat(mdocVerifier().verify(mdoc(dcApiTranscript(ORIGIN, THUMBPRINT)), dcApi(ORIGIN)).claims())
                .containsKey(TestWallet.MDOC_PID_DOCTYPE);
        assertThat(mdocVerifier().verify(mdoc(dcApiTranscript(OTHER_ORIGIN, THUMBPRINT)),
                dcApi(ORIGIN, OTHER_ORIGIN)).claims()).containsKey(TestWallet.MDOC_PID_DOCTYPE);
    }

    @Test
    void mdoc_unencryptedDcApi_usesANullThumbprint() {
        final VerificationContext plain = new VerificationContext(CLIENT_ID, NONCE, null, null, Instant.now(),
                Duration.ofSeconds(60), anchors, new StatusPolicy(false, StatusPolicy.OnUnavailable.FAIL_CLOSED,
                Duration.ofSeconds(900), List.of()), Set.of(), TestWallet.MDOC_PID_DOCTYPE, false)
                .forDcApi(List.of(ORIGIN));

        assertThat(mdocVerifier().verify(mdoc(dcApiTranscript(ORIGIN, null)), plain).claims())
                .containsKey(TestWallet.MDOC_PID_DOCTYPE);
        refused(() -> mdocVerifier().verify(mdoc(dcApiTranscript(ORIGIN, THUMBPRINT)), plain),
                WalletErrorCode.HOLDER_BINDING_INVALID);
    }

    @Test
    void mdoc_anotherOrigin_isRefused() {
        refused(() -> mdocVerifier().verify(mdoc(dcApiTranscript(EVIL_ORIGIN, THUMBPRINT)), dcApi(ORIGIN)),
                WalletErrorCode.HOLDER_BINDING_INVALID);
    }

    @Test
    void mdoc_redirectTranscript_isRefusedOverTheDcApi_andViceVersa() {
        refused(() -> mdocVerifier().verify(mdoc(redirectTranscript()), dcApi(ORIGIN)),
                WalletErrorCode.HOLDER_BINDING_INVALID);
        refused(() -> mdocVerifier().verify(mdoc(dcApiTranscript(ORIGIN, THUMBPRINT)), redirect()),
                WalletErrorCode.HOLDER_BINDING_INVALID);
        assertThat(mdocVerifier().verify(mdoc(redirectTranscript()), redirect()).claims())
                .containsKey(TestWallet.MDOC_PID_DOCTYPE);
    }

    // ------------------------------------------------------------------ context

    @Test
    void forDcApi_needsAtLeastOneBareOrigin() {
        assertThatThrownBy(() -> redirect().forDcApi(List.of())).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> redirect().forDcApi(List.of("origin:" + ORIGIN)))
                .isInstanceOf(IllegalArgumentException.class);
        assertThat(redirect().dcApi()).isFalse();
        assertThat(dcApi(ORIGIN).dcApi()).isTrue();
    }
}
