/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.wallet.mdoc;

import com.nimbusds.jose.jwk.Curve;
import io.helixiam.authorization.federation.wallet.VerificationContext;
import io.helixiam.authorization.federation.wallet.VerifiedPresentation;
import io.helixiam.authorization.federation.wallet.WalletErrorCode;
import io.helixiam.authorization.federation.wallet.WalletVerificationException;
import io.helixiam.authorization.federation.wallet.status.CredentialIssuer;
import io.helixiam.authorization.federation.wallet.status.StatusEvaluator;
import io.helixiam.authorization.federation.wallet.status.StatusPolicy;
import io.helixiam.authorization.federation.wallet.status.StatusReference;
import io.helixiam.authorization.federation.wallet.testwallet.TestPki;
import io.helixiam.authorization.federation.wallet.testwallet.TestWallet;
import io.helixiam.authorization.federation.wallet.testwallet.TestWallet.CborTag;
import io.helixiam.authorization.federation.wallet.testwallet.TestWallet.IssuedItem;
import io.helixiam.authorization.federation.wallet.testwallet.TestWallet.MdocCredential;
import io.helixiam.authorization.federation.wallet.trust.IssuerTrustValidator;
import io.helixiam.authorization.federation.wallet.trust.TrustAnchors;
import io.helixiam.authorization.federation.wallet.trust.TrustAnchors.RevocationMode;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * {@link MdocPresentationVerifier}: every step of the mdoc verification (docs/eudi-wallet-spec-notes.md §1.9, §6) has a
 * positive and at least one negative test. Credentials and DeviceResponses come from {@link TestWallet}; the expected
 * SessionTranscript is built here with Jackson's CBOR writer, independently of {@link SessionTranscripts}. Each
 * negative test changes exactly one thing in an otherwise valid presentation.
 */
class MdocPresentationVerifierTest {

    private static final String CLIENT_ID = "x509_hash:Uvo3HtuIxuhC92rShpgqcT3YXwrqRxWEviRiA0OZszk";
    private static final String NONCE = "exc7gBkxjx1rdc9udRrveKvSsJIq80avlXeLHhGwqtA";
    private static final String RESPONSE_URI = "https://verifier.example/wallet/response";
    private static final String NS = TestWallet.MDOC_PID_DOCTYPE;
    private static final StatusReference STATUS_REF = new StatusReference(42, "https://status.example/lists/1");

    private static TestWallet wallet;
    private static TrustAnchors anchors;

    private final AtomicReference<StatusReference> evaluated = new AtomicReference<>();
    private StatusEvaluator status = (ref, a, issuer) -> {
        evaluated.set(ref);
        return StatusEvaluator.VALID;
    };

    @BeforeAll
    static void setUp() {
        wallet = TestWallet.create();
        anchors = wallet.pki().trustAnchors(RevocationMode.OFF);
    }

    // ------------------------------------------------------------------------------------------- fixtures

    private static Map<String, Object> pidClaims() {
        final Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("given_name", "Erika");                                  // digestID 0
        claims.put("family_name", "Mustermann");                            // digestID 1
        claims.put("birth_date", new CborTag(1004, "1964-08-12"));          // digestID 2
        claims.put("nationality", List.of("DE"));                           // digestID 3
        claims.put("place_of_birth", Map.of("locality", "Berlin"));         // digestID 4
        claims.put("sex", 2);                                               // digestID 5
        claims.put("portrait", new byte[] {(byte) 0xff, (byte) 0xd8, 1});   // digestID 6
        claims.put("issuance_date", new CborTag(0, "2026-01-02T03:04:05Z")); // digestID 7
        claims.put("personal_administrative_number", "PAN-0001");          // digestID 8
        return claims;
    }

    private static MdocCredential pid(final Optional<StatusReference> statusRef) {
        final Instant now = Instant.now();
        return wallet.mdocPid(pidClaims(), now.minusSeconds(3600), now.minusSeconds(3600), now.plus(Duration.ofDays(30)),
                statusRef);
    }

    private static MdocCredential pid() {
        return pid(Optional.of(STATUS_REF));
    }

    private static MdocCredential pidWithMso(final Consumer<Map<Object, Object>> msoEdit) {
        final Instant now = Instant.now();
        return wallet.mdocPid(pidClaims(), now.minusSeconds(3600), now.minusSeconds(3600), now.plus(Duration.ofDays(30)),
                msoEdit);
    }

    /** The OpenID4VP redirect SessionTranscript, written with Jackson (independent of production code). */
    private static byte[] transcript(final String clientId, final String nonce, final byte[] thumbprint,
            final String responseUri) {
        final byte[] info = TestWallet.cbor(Arrays.asList(clientId, nonce, thumbprint, responseUri));
        return TestWallet.cbor(Arrays.asList(null, null,
                List.of("OpenID4VPHandover", TestWallet.sha("SHA-256", info))));
    }

    private static byte[] transcript() {
        return transcript(CLIENT_ID, NONCE, null, RESPONSE_URI);
    }

    private static Map<Object, Object> response(final MdocCredential cred) {
        return TestWallet.mdocDeviceResponseStructure(cred, pidClaims().keySet(), transcript());
    }

    private static String encode(final Map<Object, Object> response) {
        return TestWallet.b64url(TestWallet.cbor(response));
    }

    private static String presentAll(final MdocCredential cred) {
        return encode(response(cred));
    }

    @SuppressWarnings("unchecked")
    private static Map<Object, Object> document(final Map<Object, Object> response) {
        return (Map<Object, Object>) ((List<Object>) response.get("documents")).get(0);
    }

    @SuppressWarnings("unchecked")
    private static Map<Object, Object> issuerSigned(final Map<Object, Object> response) {
        return (Map<Object, Object>) document(response).get("issuerSigned");
    }

    @SuppressWarnings("unchecked")
    private static Map<Object, Object> deviceSigned(final Map<Object, Object> response) {
        return (Map<Object, Object>) document(response).get("deviceSigned");
    }

    @SuppressWarnings("unchecked")
    private static Map<Object, Object> deviceAuth(final Map<Object, Object> response) {
        return (Map<Object, Object>) deviceSigned(response).get("deviceAuth");
    }

    @SuppressWarnings("unchecked")
    private static List<Object> items(final Map<Object, Object> response) {
        return (List<Object>) ((Map<Object, Object>) issuerSigned(response).get("nameSpaces")).get(NS);
    }

    @SuppressWarnings("unchecked")
    private static List<Object> issuerAuth(final Map<Object, Object> response) {
        return (List<Object>) issuerSigned(response).get("issuerAuth");
    }

    private static VerificationContext context() {
        return context(Instant.now(), null, false, StatusPolicy.OnUnavailable.FAIL_CLOSED, NS);
    }

    private static VerificationContext context(final Instant now, final byte[] thumbprint,
            final boolean statusRequired, final StatusPolicy.OnUnavailable onUnavailable, final String doctype) {
        return new VerificationContext(CLIENT_ID, NONCE, RESPONSE_URI, thumbprint, now, Duration.ofSeconds(60),
                anchors, new StatusPolicy(statusRequired, onUnavailable, Duration.ofSeconds(900), List.of()),
                Set.of(), doctype, false);
    }

    private static VerificationContext failOpenContext() {
        return context(Instant.now(), null, false, StatusPolicy.OnUnavailable.FAIL_OPEN_WITH_AUDIT, NS);
    }

    private static VerificationContext contextAt(final Instant now) {
        return context(now, null, false, StatusPolicy.OnUnavailable.FAIL_CLOSED, NS);
    }

    private MdocPresentationVerifier verifier() {
        return new MdocPresentationVerifier(new IssuerTrustValidator(), status);
    }

    private VerifiedPresentation verify(final String presentation) {
        return verifier().verify(presentation, context());
    }

    private void assertRejected(final String presentation, final VerificationContext ctx, final WalletErrorCode code) {
        assertThatThrownBy(() -> verifier().verify(presentation, ctx))
                .isInstanceOf(WalletVerificationException.class)
                .satisfies(e -> assertThat(((WalletVerificationException) e).code()).isEqualTo(code));
    }

    private void assertRejected(final String presentation, final WalletErrorCode code) {
        assertRejected(presentation, context(), code);
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> pidNamespace(final VerifiedPresentation result) {
        return (Map<String, Object>) result.claims().get(NS);
    }

    // ------------------------------------------------------------------------------------------- positive

    @Test
    void formatIsMsoMdoc() {
        assertThat(verifier().format()).isEqualTo("mso_mdoc");
    }

    @Test
    void fullPidIsVerifiedAndClaimsAreNormalised() {
        final VerifiedPresentation result = verify(presentAll(pid()));

        assertThat(result.format()).isEqualTo("mso_mdoc");
        assertThat(result.claims()).containsOnlyKeys(NS);
        assertThat(pidNamespace(result))
                .containsOnlyKeys(pidClaims().keySet().toArray(String[]::new))
                .containsEntry("given_name", "Erika")
                .containsEntry("birth_date", "1964-08-12")
                .containsEntry("nationality", List.of("DE"))
                .containsEntry("place_of_birth", Map.of("locality", "Berlin"))
                .containsEntry("sex", 2L)
                .containsEntry("portrait", TestWallet.b64url(new byte[] {(byte) 0xff, (byte) 0xd8, 1}))
                .containsEntry("issuance_date", "2026-01-02T03:04:05Z")
                .containsEntry("personal_administrative_number", "PAN-0001");
        assertThat(result.issuerSubjectDn())
                .isEqualTo(wallet.issuer().certificate().getSubjectX500Principal().getName());
        // Pinned to the PKIX-validated leaf (IssuerTrustValidator#validateChain -> ValidatedChain#leaf()), not merely
        // some certificate on the presented x5chain: the intermediate CA has a different, distinguishable subject.
        assertThat(result.issuerSubjectDn())
                .isNotEqualTo(wallet.pki().intermediate().getSubjectX500Principal().getName());
        assertThat(result.issuerSerialHex()).isEqualTo(wallet.issuer().certificate().getSerialNumber().toString(16));
        assertThat(result.statusResult()).isEqualTo(StatusEvaluator.VALID);
        assertThat(evaluated.get()).isEqualTo(STATUS_REF);
    }

    @Test
    void credentialTypeIsTheDocType() {
        assertThat(verify(presentAll(pid())).credentialType()).isEqualTo(TestWallet.MDOC_PID_DOCTYPE);
    }

    @Test
    void undisclosedItemsAreAbsent() {
        final String vp = TestWallet.b64url(TestWallet.mdocDeviceResponse(pid(), Set.of("given_name"), transcript()));

        assertThat(pidNamespace(verify(vp))).containsOnlyKeys("given_name");
    }

    @Test
    void sha384DigestsAreVerified() {
        final Instant now = Instant.now();
        final MdocCredential cred = wallet.mdoc(NS, "SHA-384", List.of(IssuedItem.of(0, "given_name", "Erika")),
                now.minusSeconds(60), now.minusSeconds(60), now.plusSeconds(3600), mso -> { });
        final String vp = TestWallet.b64url(TestWallet.mdocDeviceResponse(cred, Set.of("given_name"), transcript()));

        assertThat(pidNamespace(verify(vp))).containsEntry("given_name", "Erika");
    }

    @Test
    void itemIsDigestedExactlyAsReceivedNeverReEncoded() {
        // digestID 5 written with a non-preferred one-byte argument (18 05): a re-encoding verifier would hash 05.
        final ByteArrayOutputStream item = new ByteArrayOutputStream();
        item.write(0xa4);
        item.writeBytes(TestWallet.cbor("digestID"));
        item.write(0x18);
        item.write(0x05);
        item.writeBytes(TestWallet.cbor("random"));
        item.writeBytes(TestWallet.cbor(new byte[16]));
        item.writeBytes(TestWallet.cbor("elementIdentifier"));
        item.writeBytes(TestWallet.cbor("given_name"));
        item.writeBytes(TestWallet.cbor("elementValue"));
        item.writeBytes(TestWallet.cbor("Erika"));
        final Instant now = Instant.now();
        final MdocCredential cred = wallet.mdoc(NS, "SHA-256",
                List.of(new IssuedItem("given_name", 5, item.toByteArray())),
                now.minusSeconds(60), now.minusSeconds(60), now.plusSeconds(3600), mso -> { });
        final String vp = TestWallet.b64url(TestWallet.mdocDeviceResponse(cred, Set.of("given_name"), transcript()));

        assertThat(pidNamespace(verify(vp))).containsEntry("given_name", "Erika");
    }

    @Test
    void encryptedResponseTranscriptCarriesTheThumbprint() {
        final byte[] thumbprint = TestWallet.sha("SHA-256", "verifier-encryption-key".getBytes(StandardCharsets.UTF_8));
        final MdocCredential cred = pid();
        final String vp = TestWallet.b64url(TestWallet.mdocDeviceResponse(cred, pidClaims().keySet(),
                transcript(CLIENT_ID, NONCE, thumbprint, RESPONSE_URI)));
        final VerificationContext ctx = context(Instant.now(), thumbprint, false,
                StatusPolicy.OnUnavailable.FAIL_CLOSED, NS);

        assertThat(verifier().verify(vp, ctx).claims()).containsKey(NS);
        // the same presentation with the unencrypted (null thumbprint) transcript does not hold
        assertRejected(presentAll(cred), ctx, WalletErrorCode.HOLDER_BINDING_INVALID);
    }

    // ------------------------------------------------------------------------------------------- input and limits

    @Test
    void presentationOverTheSizeCapIsLimitExceeded() {
        assertRejected("A".repeat(64 * 1024 + 1), WalletErrorCode.LIMIT_EXCEEDED);
    }

    @Test
    void cborDepthBombIsLimitExceeded() {
        final byte[] bomb = new byte[41];
        Arrays.fill(bomb, (byte) 0x81); // [[[[...]]]] 40 deep
        bomb[40] = 0;

        assertRejected(TestWallet.b64url(bomb), WalletErrorCode.LIMIT_EXCEEDED);
    }

    @Test
    void nonBase64UrlOrNonCborIsInvalidResponse() {
        assertRejected("not base64url!", WalletErrorCode.INVALID_RESPONSE);
        assertRejected(presentAll(pid()) + "=", WalletErrorCode.INVALID_RESPONSE);
        assertRejected(TestWallet.b64url(new byte[] {(byte) 0xff}), WalletErrorCode.INVALID_RESPONSE);
        assertRejected(TestWallet.b64url(TestWallet.cbor(List.of())), WalletErrorCode.INVALID_RESPONSE);
        assertRejected("", WalletErrorCode.INVALID_RESPONSE);
    }

    // ------------------------------------------------------------------------------------------- DeviceResponse

    @Test
    void responseStatusOtherThanZeroIsInvalidResponse() {
        final Map<Object, Object> response = response(pid());
        response.put("status", 10);

        assertRejected(encode(response), WalletErrorCode.INVALID_RESPONSE);
    }

    @Test
    void responseMustCarryExactlyOneDocument() {
        final Map<Object, Object> none = response(pid());
        none.put("documents", List.of());
        assertRejected(encode(none), WalletErrorCode.INVALID_RESPONSE);

        final Map<Object, Object> two = response(pid());
        two.put("documents", List.of(document(two), document(two)));
        assertRejected(encode(two), WalletErrorCode.INVALID_RESPONSE);

        final Map<Object, Object> missing = response(pid());
        missing.remove("documents");
        assertRejected(encode(missing), WalletErrorCode.INVALID_RESPONSE);
    }

    @Test
    void zkOrEncryptedDocumentsAreRefused() {
        for (final String member : List.of("zkDocuments", "encryptedDocuments")) {
            final Map<Object, Object> response = response(pid());
            response.put(member, List.of());
            assertRejected(encode(response), WalletErrorCode.INVALID_RESPONSE);
        }
    }

    @Test
    void wrongVersionIsInvalidResponse() {
        final Map<Object, Object> response = response(pid());
        response.put("version", "2.0");

        assertRejected(encode(response), WalletErrorCode.INVALID_RESPONSE);
    }

    @Test
    void documentDocTypeNotAcceptedIsDoctypeNotAccepted() {
        assertRejected(presentAll(pid()), context(Instant.now(), null, false,
                StatusPolicy.OnUnavailable.FAIL_CLOSED, "org.iso.18013.5.1.mDL"), WalletErrorCode.DOCTYPE_NOT_ACCEPTED);
    }

    @Test
    void msoDocTypeDifferentFromTheDocumentIsDoctypeNotAccepted() {
        final MdocCredential cred = pidWithMso(mso -> mso.put("docType", "org.iso.18013.5.1.mDL"));

        assertRejected(presentAll(cred), WalletErrorCode.DOCTYPE_NOT_ACCEPTED);
    }

    // ------------------------------------------------------------------------------------------- IssuerAuth

    @Test
    void untrustedIssuerChainIsIssuerUntrusted() {
        final TestWallet other = TestWallet.create();
        final Instant now = Instant.now();
        final MdocCredential cred = other.mdocPid(pidClaims(), now.minusSeconds(60), now.minusSeconds(60),
                now.plusSeconds(3600), Optional.empty());

        assertRejected(presentAll(cred), WalletErrorCode.ISSUER_UNTRUSTED);
    }

    @Test
    void untrustedIssuerIsReportedBeforeMissingDeviceAuth() {
        final TestWallet other = TestWallet.create();
        final Instant now = Instant.now();
        final Map<Object, Object> response = response(other.mdocPid(pidClaims(), now.minusSeconds(60),
                now.minusSeconds(60), now.plusSeconds(3600), Optional.empty()));
        document(response).remove("deviceSigned");

        assertRejected(encode(response), WalletErrorCode.ISSUER_UNTRUSTED);
    }

    @Test
    void msoSwappedUnderTheIssuerSignatureIsIssuerSignatureInvalid() {
        final Map<Object, Object> response = response(pid());
        issuerAuth(response).set(2, pid().mso()); // another, equally well-formed MSO

        assertRejected(encode(response), WalletErrorCode.ISSUER_SIGNATURE_INVALID);
    }

    @Test
    void detachedIssuerAuthPayloadIsInvalidResponse() {
        final Map<Object, Object> response = response(pid());
        issuerAuth(response).set(2, null);

        assertRejected(encode(response), WalletErrorCode.INVALID_RESPONSE);
    }

    @Test
    void missingIssuerAuthIsInvalidResponse() {
        final Map<Object, Object> response = response(pid());
        issuerSigned(response).remove("issuerAuth");

        assertRejected(encode(response), WalletErrorCode.INVALID_RESPONSE);
    }

    // ------------------------------------------------------------------------------------------- validity

    @Test
    void expiredMsoIsCredentialExpired() {
        final Instant now = Instant.now();
        final MdocCredential cred = wallet.mdocPid(pidClaims(), now.minusSeconds(3600), now.minusSeconds(3600),
                now.minusSeconds(120), Optional.empty());

        assertRejected(presentAll(cred), WalletErrorCode.CREDENTIAL_EXPIRED);
    }

    @Test
    void expiryWithinTheSkewIsAccepted() {
        final Instant now = Instant.now();
        final MdocCredential cred = wallet.mdocPid(pidClaims(), now.minusSeconds(3600), now.minusSeconds(3600),
                now.minusSeconds(30), Optional.empty());

        assertThat(verify(presentAll(cred)).statusResult()).isEqualTo("ABSENT");
    }

    @Test
    void validityIsCheckedAgainstContextNowNotTheClock() {
        final Instant now = Instant.now();
        final MdocCredential cred = wallet.mdocPid(pidClaims(), now.minusSeconds(3600), now.minusSeconds(3600),
                now.plus(Duration.ofDays(1)), Optional.empty());

        assertRejected(presentAll(cred), contextAt(now.plus(Duration.ofDays(2))), WalletErrorCode.CREDENTIAL_EXPIRED);
    }

    @Test
    void validFromInTheFutureIsCredentialNotYetValid() {
        final Instant now = Instant.now();
        final MdocCredential cred = wallet.mdocPid(pidClaims(), now.minusSeconds(3600), now.plusSeconds(600),
                now.plus(Duration.ofDays(1)), Optional.empty());

        assertRejected(presentAll(cred), WalletErrorCode.CREDENTIAL_NOT_YET_VALID);
    }

    @Test
    void signedInTheFutureBeyondTheSkewIsInvalidResponse() {
        final Instant now = Instant.now();
        final MdocCredential cred = wallet.mdocPid(pidClaims(), now.plusSeconds(600), now.plusSeconds(600),
                now.plus(Duration.ofDays(1)), Optional.empty());

        assertRejected(presentAll(cred), WalletErrorCode.INVALID_RESPONSE);
    }

    @Test
    void signedAndValidFromWithinTheSkewAreAccepted() {
        final Instant now = Instant.now();
        final MdocCredential cred = wallet.mdocPid(pidClaims(), now.plusSeconds(30), now.plusSeconds(30),
                now.plus(Duration.ofDays(1)), Optional.empty());

        assertThat(verify(presentAll(cred)).claims()).containsKey(NS);
    }

    @Test
    void msoValidUntilAfterTheIssuerCertificateIsInvalidResponse() {
        final Instant now = Instant.now();
        final TestWallet shortCert = wallet.withIssuer(wallet.pki().issueLeaf(TestPki.LeafSpec.defaults()
                .withValidity(now.minus(Duration.ofDays(1)), now.plus(Duration.ofDays(10)))), null);
        final MdocCredential cred = shortCert.mdocPid(pidClaims(), now.minusSeconds(60), now.minusSeconds(60),
                now.plus(Duration.ofDays(30)), Optional.empty());

        assertRejected(presentAll(cred), WalletErrorCode.INVALID_RESPONSE);
    }

    @Test
    void msoValidFromBeforeTheIssuerCertificateIsInvalidResponse() {
        final Instant now = Instant.now();
        final TestWallet lateCert = wallet.withIssuer(wallet.pki().issueLeaf(TestPki.LeafSpec.defaults()
                .withValidity(now.minus(Duration.ofHours(1)), now.plus(Duration.ofDays(365)))), null);
        final MdocCredential cred = lateCert.mdocPid(pidClaims(), now.minus(Duration.ofHours(2)),
                now.minus(Duration.ofHours(2)), now.plus(Duration.ofDays(30)), Optional.empty());

        assertRejected(presentAll(cred), WalletErrorCode.INVALID_RESPONSE);
    }

    // ------------------------------------------------------------------------------------------- digests

    @Test
    void tamperedItemValueIsDigestMismatch() {
        final Map<Object, Object> response = response(pid());
        items(response).set(0, new CborTag(24, IssuedItem.of(0, "given_name", "Eve").encoded()));

        assertRejected(encode(response), WalletErrorCode.DIGEST_MISMATCH);
    }

    @Test
    void itemWhoseDigestIdIsNotInTheMsoIsDigestMismatch() {
        final Map<Object, Object> response = response(pid());
        items(response).add(new CborTag(24, IssuedItem.of(99, "age_over_18", true).encoded()));

        assertRejected(encode(response), WalletErrorCode.DIGEST_MISMATCH);
    }

    @Test
    @SuppressWarnings("unchecked")
    void itemInANamespaceTheMsoDoesNotDigestIsDigestMismatch() {
        final Map<Object, Object> response = response(pid());
        final Map<Object, Object> nameSpaces = (Map<Object, Object>) issuerSigned(response).get("nameSpaces");
        nameSpaces.put("eu.europa.ec.eudi.pid.de.1", new ArrayList<>(items(response)));

        assertRejected(encode(response), WalletErrorCode.DIGEST_MISMATCH);
    }

    @Test
    void duplicateDigestIdInANamespaceIsInvalidResponse() {
        final Instant now = Instant.now();
        final MdocCredential cred = wallet.mdoc(NS, "SHA-256",
                List.of(IssuedItem.of(0, "given_name", "Erika"), IssuedItem.of(0, "family_name", "Mustermann")),
                now.minusSeconds(60), now.minusSeconds(60), now.plusSeconds(3600), mso -> { });
        final String vp = TestWallet.b64url(TestWallet.mdocDeviceResponse(cred, Set.of("given_name", "family_name"),
                transcript()));

        assertRejected(vp, WalletErrorCode.INVALID_RESPONSE);
    }

    @Test
    void duplicateElementIdentifierIsInvalidResponse() {
        final Instant now = Instant.now();
        final IssuedItem second = IssuedItem.of(1, "given_name", "Eve");
        final MdocCredential cred = wallet.mdoc(NS, "SHA-256",
                List.of(IssuedItem.of(0, "given_name", "Erika"),
                        new IssuedItem("given_name#2", second.digestId(), second.encoded())),
                now.minusSeconds(60), now.minusSeconds(60), now.plusSeconds(3600), mso -> { });
        final String vp = TestWallet.b64url(TestWallet.mdocDeviceResponse(cred, Set.of("given_name", "given_name#2"),
                transcript()));

        assertRejected(vp, WalletErrorCode.INVALID_RESPONSE);
    }

    @Test
    void malformedItemsAreInvalidResponse() {
        final Map<Object, Object> notTagged = response(pid());
        items(notTagged).set(0, IssuedItem.of(0, "given_name", "Erika").encoded());
        assertRejected(encode(notTagged), WalletErrorCode.INVALID_RESPONSE);

        final Map<Object, Object> emptyList = response(pid());
        items(emptyList).clear();
        assertRejected(encode(emptyList), WalletErrorCode.INVALID_RESPONSE);

        final Map<Object, Object> shortRandom = response(pid());
        final Map<Object, Object> item = new LinkedHashMap<>();
        item.put("digestID", 0);
        item.put("random", new byte[8]);
        item.put("elementIdentifier", "given_name");
        item.put("elementValue", "Erika");
        items(shortRandom).set(0, new CborTag(24, TestWallet.cbor(item)));
        assertRejected(encode(shortRandom), WalletErrorCode.INVALID_RESPONSE);
    }

    @Test
    void invalidFullDateIsInvalidResponse() {
        final Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("birth_date", new CborTag(1004, "1964-13-45"));
        final Instant now = Instant.now();
        final MdocCredential cred = wallet.mdocPid(claims, now.minusSeconds(60), now.minusSeconds(60),
                now.plusSeconds(3600), Optional.empty());
        final String vp = TestWallet.b64url(TestWallet.mdocDeviceResponse(cred, claims.keySet(), transcript()));

        assertRejected(vp, WalletErrorCode.INVALID_RESPONSE);
    }

    // ------------------------------------------------------------------------------------------- DeviceAuth

    /**
     * The transcript is hashed inside the detached device signature, so a verifier cannot tell which transcript input
     * (nonce, client_id, response_uri, thumbprint) differed: every mismatch is {@code HOLDER_BINDING_INVALID}, never
     * {@code NONCE_MISMATCH} / {@code AUDIENCE_MISMATCH}.
     */
    @Test
    void transcriptWithAnotherNonceIsHolderBindingInvalidNotNonceMismatch() {
        final String vp = TestWallet.b64url(TestWallet.mdocDeviceResponse(pid(), pidClaims().keySet(),
                transcript(CLIENT_ID, "another-nonce", null, RESPONSE_URI)));

        assertRejected(vp, WalletErrorCode.HOLDER_BINDING_INVALID);
    }

    /** See {@link #transcriptWithAnotherNonceIsHolderBindingInvalidNotNonceMismatch()}. */
    @Test
    void transcriptWithAnotherClientIdIsHolderBindingInvalidNotAudienceMismatch() {
        final String vp = TestWallet.b64url(TestWallet.mdocDeviceResponse(pid(), pidClaims().keySet(),
                transcript("x509_san_dns:attacker.example", NONCE, null, RESPONSE_URI)));

        assertRejected(vp, WalletErrorCode.HOLDER_BINDING_INVALID);
    }

    @Test
    void transcriptWithAnotherResponseUriIsHolderBindingInvalid() {
        final String vp = TestWallet.b64url(TestWallet.mdocDeviceResponse(pid(), pidClaims().keySet(),
                transcript(CLIENT_ID, NONCE, null, "https://attacker.example/response")));

        assertRejected(vp, WalletErrorCode.HOLDER_BINDING_INVALID);
    }

    @Test
    void deviceSignatureByAnotherKeyIsHolderBindingInvalid() {
        final MdocCredential cred = pid();
        final MdocCredential otherKey = new MdocCredential(cred.docType(), cred.issuerAuth(), cred.mso(),
                cred.items(), TestWallet.ecKey(Curve.P_256));
        final Map<Object, Object> response = response(cred);
        deviceAuth(response).put("deviceSignature", TestWallet.deviceSignature(otherKey, transcript(),
                new CborTag(24, TestWallet.cbor(Map.of()))));

        assertRejected(encode(response), WalletErrorCode.HOLDER_BINDING_INVALID);
    }

    @Test
    void deviceSignatureWithAnAttachedPayloadIsHolderBindingInvalid() {
        final Map<Object, Object> response = response(pid());
        @SuppressWarnings("unchecked")
        final List<Object> signature = (List<Object>) deviceAuth(response).get("deviceSignature");
        signature.set(2, new byte[] {1});

        assertRejected(encode(response), WalletErrorCode.HOLDER_BINDING_INVALID);
    }

    @Test
    void missingDeviceAuthIsHolderBindingMissing() {
        final Map<Object, Object> noDeviceAuth = response(pid());
        deviceSigned(noDeviceAuth).remove("deviceAuth");
        assertRejected(encode(noDeviceAuth), WalletErrorCode.HOLDER_BINDING_MISSING);

        final Map<Object, Object> emptyDeviceAuth = response(pid());
        deviceAuth(emptyDeviceAuth).clear();
        assertRejected(encode(emptyDeviceAuth), WalletErrorCode.HOLDER_BINDING_MISSING);

        final Map<Object, Object> noDeviceSigned = response(pid());
        document(noDeviceSigned).remove("deviceSigned");
        assertRejected(encode(noDeviceSigned), WalletErrorCode.HOLDER_BINDING_MISSING);
    }

    private static List<Object> deviceMac() {
        final List<Object> mac = new ArrayList<>();
        mac.add(TestWallet.cbor(Map.of(1, 5))); // HMAC 256/256
        mac.add(new LinkedHashMap<>());
        mac.add(null);
        mac.add(new byte[32]);
        return mac;
    }

    @Test
    void deviceMacIsHolderBindingInvalid() {
        final Map<Object, Object> response = response(pid());
        deviceAuth(response).clear();
        deviceAuth(response).put("deviceMac", new CborTag(17, deviceMac()));

        assertRejected(encode(response), WalletErrorCode.HOLDER_BINDING_INVALID);
    }

    @Test
    void deviceMacNextToADeviceSignatureIsHolderBindingInvalid() {
        final Map<Object, Object> response = response(pid());
        deviceAuth(response).put("deviceMac", deviceMac());

        assertRejected(encode(response), WalletErrorCode.HOLDER_BINDING_INVALID);
    }

    @Test
    void nonEmptyDeviceNameSpacesAreRefusedEvenWhenSigned() {
        final MdocCredential cred = pid();
        final CborTag deviceNameSpaces = new CborTag(24, TestWallet.cbor(Map.of(NS, Map.of("given_name", "Eve"))));
        final Map<Object, Object> response = response(cred);
        deviceSigned(response).put("nameSpaces", deviceNameSpaces);
        deviceAuth(response).put("deviceSignature", TestWallet.deviceSignature(cred, transcript(), deviceNameSpaces));

        assertRejected(encode(response), WalletErrorCode.INVALID_RESPONSE);
    }

    @Test
    void deviceNameSpacesAreBoundByTheDeviceSignature() {
        final Map<Object, Object> response = response(pid());
        // a different (still empty, still definite-length) encoding of the map: a0 (direct) vs b8 00 (1-byte
        // extended length form of 0) — same semantics, different bytes, so the signature must not verify.
        deviceSigned(response).put("nameSpaces", new CborTag(24, new byte[] {(byte) 0xb8, 0x00}));

        assertRejected(encode(response), WalletErrorCode.HOLDER_BINDING_INVALID);
    }

    @Test
    void statusIsNotEvaluatedWhenDeviceAuthFails() {
        final String vp = TestWallet.b64url(TestWallet.mdocDeviceResponse(pid(), pidClaims().keySet(),
                transcript(CLIENT_ID, "another-nonce", null, RESPONSE_URI)));
        status = (ref, a, issuer) -> {
            evaluated.set(ref);
            throw new WalletVerificationException(WalletErrorCode.CREDENTIAL_REVOKED, "revoked");
        };

        assertRejected(vp, WalletErrorCode.HOLDER_BINDING_INVALID);
        assertThat(evaluated.get()).isNull();
    }

    // ------------------------------------------------------------------------------------------- status

    @Test
    void revokedStatusIsCredentialRevoked() {
        status = (ref, a, issuer) -> {
            throw new WalletVerificationException(WalletErrorCode.CREDENTIAL_REVOKED, "revoked");
        };

        assertRejected(presentAll(pid()), WalletErrorCode.CREDENTIAL_REVOKED);
    }

    @Test
    void statusEvaluatorReceivesTheConfiguredAnchors() {
        final AtomicReference<TrustAnchors> seen = new AtomicReference<>();
        status = (ref, a, issuer) -> {
            seen.set(a);
            return StatusEvaluator.VALID;
        };

        verify(presentAll(pid()));

        assertThat(seen.get()).isSameAs(anchors);
    }

    @Test
    void statusEvaluatorReceivesTheIssuerAuthChainAndTheStatusListCertificate() throws Exception {
        final AtomicReference<CredentialIssuer> seen = new AtomicReference<>();
        status = (ref, a, issuer) -> {
            seen.set(issuer);
            return StatusEvaluator.VALID;
        };
        final byte[] certificate = wallet.pki().intermediate().getEncoded();
        final MdocCredential withCertificate = pidWithMso(mso -> mso.put("status", Map.of("status_list",
                Map.of("idx", 42, "uri", "https://status.example/lists/1", "certificate", certificate))));

        verify(presentAll(pid()));
        assertThat(seen.get().chain()).isEqualTo(wallet.issuer().chain());
        assertThat(seen.get().statusListCertificate()).isNull();

        verify(presentAll(withCertificate));
        assertThat(seen.get().chain()).isEqualTo(wallet.issuer().chain());
        assertThat(seen.get().statusListCertificate()).isEqualTo(certificate);
    }

    @Test
    void anythingButValidFromTheEvaluatorIsStatusUnavailable() {
        status = (ref, a, issuer) -> "SUSPENDED";
        assertRejected(presentAll(pid()), WalletErrorCode.STATUS_UNAVAILABLE);

        status = (ref, a, issuer) -> {
            throw new IllegalStateException("boom");
        };
        assertRejected(presentAll(pid()), WalletErrorCode.STATUS_UNAVAILABLE);
    }

    @Test
    void unreachableEvaluatorFollowsFailOpen() {
        status = (ref, a, issuer) -> {
            throw new IllegalStateException("network down");
        };

        assertThat(verifier().verify(presentAll(pid()), failOpenContext()).statusResult())
                .isEqualTo(MdocPresentationVerifier.STATUS_UNAVAILABLE_ACCEPTED);
    }

    @Test
    void nonValidEvaluatorAnswerIsNeverAcceptedEvenWhenFailOpen() {
        status = (ref, a, issuer) -> "REVOKED";

        assertRejected(presentAll(pid()), failOpenContext(), WalletErrorCode.STATUS_UNAVAILABLE);
    }

    @Test
    void absentStatusIsAbsentAndNeverEvaluated() {
        final VerifiedPresentation result = verify(presentAll(pid(Optional.empty())));

        assertThat(result.statusResult()).isEqualTo(MdocPresentationVerifier.STATUS_ABSENT);
        assertThat(evaluated.get()).isNull();
    }

    @Test
    void absentStatusWhenRequiredIsStatusRequired() {
        assertRejected(presentAll(pid(Optional.empty())),
                context(Instant.now(), null, true, StatusPolicy.OnUnavailable.FAIL_CLOSED, NS),
                WalletErrorCode.STATUS_REQUIRED);
    }

    private static MdocCredential identifierListOnly() {
        return pidWithMso(mso -> mso.put("status", Map.of("identifier_list",
                Map.of("id", new byte[] {1, 2, 3}, "uri", "https://status.example/ids"))));
    }

    @Test
    void identifierListOnlyIsStatusUnavailableWhenFailClosed() {
        assertRejected(presentAll(identifierListOnly()), WalletErrorCode.STATUS_UNAVAILABLE);
        assertThat(evaluated.get()).isNull();
    }

    @Test
    void identifierListOnlyIsAcceptedAndRecordedWhenFailOpen() {
        final VerifiedPresentation result = verifier().verify(presentAll(identifierListOnly()), failOpenContext());

        assertThat(result.statusResult()).isEqualTo(MdocPresentationVerifier.STATUS_UNAVAILABLE_ACCEPTED)
                .isNotEqualTo(MdocPresentationVerifier.STATUS_ABSENT);
        assertThat(evaluated.get()).isNull();
    }

    @Test
    void identifierListOnlyIsNotAbsentEvenWhenStatusIsRequired() {
        assertRejected(presentAll(identifierListOnly()),
                context(Instant.now(), null, true, StatusPolicy.OnUnavailable.FAIL_CLOSED, NS),
                WalletErrorCode.STATUS_UNAVAILABLE);
    }

    @Test
    void malformedStatusIsInvalidResponse() {
        final MdocCredential cred = pidWithMso(mso -> mso.put("status",
                Map.of("status_list", Map.of("idx", -1, "uri", "https://status.example/1"))));

        assertRejected(presentAll(cred), WalletErrorCode.INVALID_RESPONSE);
    }

    // ------------------------------------------------------------------------------------------- fix round 1

    private String withDeviceSignatureHeader(final Map<Object, Object> protectedHeader) {
        final MdocCredential cred = pid();
        final Map<Object, Object> response = response(cred);
        deviceAuth(response).put("deviceSignature", TestWallet.deviceSignature(cred, transcript(),
                new CborTag(24, TestWallet.cbor(Map.of())), protectedHeader));
        return encode(response);
    }

    @Test
    void deviceSignatureAlgThatDoesNotFitTheDeviceKeyIsHolderBindingInvalid() {
        assertRejected(withDeviceSignatureHeader(Map.of(1, -35)), WalletErrorCode.HOLDER_BINDING_INVALID); // ES384
    }

    @Test
    void deviceSignatureAlgOutsideTheAllowListIsHolderBindingInvalid() {
        assertRejected(withDeviceSignatureHeader(Map.of(1, -8)), WalletErrorCode.HOLDER_BINDING_INVALID); // EdDSA
    }

    @Test
    void deviceSignatureWithoutAlgIsHolderBindingInvalid() {
        assertRejected(withDeviceSignatureHeader(Map.of(4, new byte[] {1})), WalletErrorCode.HOLDER_BINDING_INVALID);
    }

    @Test
    void issuerAuthAlgOutsideTheAllowListStaysAlgorithmNotAllowed() {
        final Map<Object, Object> response = response(pid());
        issuerAuth(response).set(0, TestWallet.cbor(Map.of(1, -8)));

        assertRejected(encode(response), WalletErrorCode.ALGORITHM_NOT_ALLOWED);
    }

    @Test
    void versionMustBeOneDotDigits() {
        for (final String version : List.of("1.", "1.0-junk", "1.x", "11.0")) {
            final Map<Object, Object> response = response(pid());
            response.put("version", version);
            assertRejected(encode(response), WalletErrorCode.INVALID_RESPONSE);
        }
        final Map<Object, Object> minor = response(pid());
        minor.put("version", "1.1");
        assertThat(verify(encode(minor)).claims()).containsKey(NS);
    }

    private static String single(final String identifier, final Object value) {
        final Map<String, Object> claims = new LinkedHashMap<>();
        claims.put(identifier, value);
        final Instant now = Instant.now();
        final MdocCredential cred = wallet.mdocPid(claims, now.minusSeconds(60), now.minusSeconds(60),
                now.plusSeconds(3600), Optional.empty());
        return TestWallet.b64url(TestWallet.mdocDeviceResponse(cred, claims.keySet(), transcript()));
    }

    @Test
    void mapElementWithIntegerKeysUsesTheirDecimalText() {
        final Map<Object, Object> value = new LinkedHashMap<>();
        value.put(1, "one");
        value.put(-2, "minus two");
        value.put("three", 3);

        assertThat(pidNamespace(verify(single("codes", value))))
                .containsEntry("codes", Map.of("1", "one", "-2", "minus two", "three", 3L));
    }

    @Test
    void integerAndTextKeyCollisionIsInvalidResponse() {
        final Map<Object, Object> value = new LinkedHashMap<>();
        value.put(1, "integer");
        value.put("1", "text");

        assertRejected(single("codes", value), WalletErrorCode.INVALID_RESPONSE);
    }

    @Test
    void fullDateMustBeExactlyYyyyMmDd() {
        for (final String date : List.of("+10000-01-01", "10000-01-01", "1964-8-12", "1964-08-12Z")) {
            assertRejected(single("birth_date", new CborTag(1004, date)), WalletErrorCode.INVALID_RESPONSE);
        }
    }

    @Test
    void tdateWithANonZOffsetIsRefused() {
        assertRejected(single("issuance_date", new CborTag(0, "2026-01-02T05:04:05+02:00")),
                WalletErrorCode.INVALID_RESPONSE);
        assertThat(pidNamespace(verify(single("issuance_date", new CborTag(0, "2026-01-02T03:04:05.250Z")))))
                .containsEntry("issuance_date", "2026-01-02T03:04:05.250Z");
    }

    /** DCQL matching (Task 14) must reject a presentation that discloses nothing; the verifier itself accepts it. */
    @Test
    void documentWithoutNameSpacesVerifiesWithEmptyClaims() {
        final Map<Object, Object> response = response(pid());
        issuerSigned(response).remove("nameSpaces");

        assertThat(verify(encode(response)).claims()).isEmpty();
    }

    @Test
    void documentErrorsNextToTheDocumentAreTolerated() {
        final Map<Object, Object> response = response(pid());
        response.put("documentErrors", List.of(Map.of("org.iso.18013.5.1.mDL", 0)));

        assertThat(verify(encode(response)).claims()).containsKey(NS);
    }

    @Test
    void customMaxPresentationBytesIsHonoured() {
        final MdocPresentationVerifier small = new MdocPresentationVerifier(new IssuerTrustValidator(), status, 100,
                CborLimits.DEFAULTS);

        assertRejected(presentAll(pid()), WalletErrorCode.LIMIT_EXCEEDED, small);
    }

    @Test
    void customCborLimitsAreHonouredForTheMso() {
        // 150 claims, one disclosed: the outer DeviceResponse stays far under 200 items, the MSO (150 digests) not
        final Map<String, Object> claims = new LinkedHashMap<>();
        for (int i = 0; i < 150; i++) {
            claims.put("c" + i, i);
        }
        final Instant now = Instant.now();
        final MdocCredential cred = wallet.mdocPid(claims, now.minusSeconds(60), now.minusSeconds(60),
                now.plusSeconds(3600), Optional.empty());
        final byte[] response = TestWallet.mdocDeviceResponse(cred, Set.of("c0"), transcript());
        final CborLimits tight = new CborLimits(16, 200, 256 * 1024);
        StrictCbor.decode(response, tight); // precondition: the outer response itself is within the tight limit

        assertThat(verify(TestWallet.b64url(response)).claims()).containsKey(NS);
        assertRejected(TestWallet.b64url(response), WalletErrorCode.LIMIT_EXCEEDED,
                new MdocPresentationVerifier(new IssuerTrustValidator(), status,
                        MdocPresentationVerifier.DEFAULT_MAX_PRESENTATION_BYTES, tight));
    }

    private static void assertRejected(final String presentation, final WalletErrorCode code,
            final MdocPresentationVerifier verifier) {
        assertThatThrownBy(() -> verifier.verify(presentation, context()))
                .isInstanceOf(WalletVerificationException.class)
                .satisfies(e -> assertThat(((WalletVerificationException) e).code()).isEqualTo(code));
    }
}
