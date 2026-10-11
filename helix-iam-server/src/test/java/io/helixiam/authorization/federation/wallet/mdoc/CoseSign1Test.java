/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.wallet.mdoc;

import io.helixiam.authorization.federation.wallet.WalletErrorCode;
import io.helixiam.authorization.federation.wallet.WalletVerificationException;
import io.helixiam.authorization.federation.wallet.testwallet.TestPki;
import io.helixiam.authorization.federation.wallet.testwallet.TestPki.KeyType;
import io.helixiam.authorization.federation.wallet.testwallet.TestPki.Leaf;
import io.helixiam.authorization.federation.wallet.testwallet.TestWallet;
import io.helixiam.authorization.federation.wallet.testwallet.TestWallet.CborTag;
import io.helixiam.authorization.federation.wallet.testwallet.TestWallet.MdocCredential;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.ValueSource;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import static io.helixiam.authorization.federation.wallet.testwallet.TestWallet.cbor;
import static io.helixiam.authorization.federation.wallet.testwallet.TestWallet.coseSign1;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * {@link CoseSign1}: decoding from the {@link StrictCbor} tree, the protected-header {@code alg} allow-list
 * (ES256/384/512), x5chain (label 33) and verification over the RFC 9052 §4.4 Sig_structure, attached and detached.
 * Signatures are produced by {@link TestWallet} with Jackson's CBOR writer and the JDK, independently of production
 * code.
 */
class CoseSign1Test {

    private static final byte[] PAYLOAD = "mdoc payload".getBytes(StandardCharsets.UTF_8);

    private static TestPki pki;
    private static Leaf p256;
    private static Leaf p384;
    private static Leaf p521;

    @BeforeAll
    static void pki() {
        pki = TestPki.create();
        p256 = pki.issueLeaf(TestPki.LeafSpec.defaults());
        p384 = pki.issueLeaf(TestPki.LeafSpec.defaults().withKeyType(KeyType.EC_P384));
        p521 = pki.issueLeaf(TestPki.LeafSpec.defaults().withKeyType(KeyType.EC_P521));
    }

    enum Alg {
        ES256(-7), ES384(-35), ES512(-36);

        final int id;

        Alg(final int id) {
            this.id = id;
        }

        Leaf leaf() {
            return switch (this) {
                case ES256 -> p256;
                case ES384 -> p384;
                case ES512 -> p521;
            };
        }
    }

    // ------------------------------------------------------------------------------------------- round trip

    @ParameterizedTest
    @EnumSource(Alg.class)
    void signVerifyRoundTrip(final Alg alg) {
        final Leaf leaf = alg.leaf();
        final CoseSign1 cose = decode(sign(Map.of(1, alg.id), Map.of(33, TestWallet.x5chain(leaf.chain())),
                PAYLOAD, leaf));

        assertThat(cose.algorithm()).isEqualTo(alg.id);
        assertThat(cose.payload()).isEqualTo(PAYLOAD);
        assertThat(cose.x5chain()).containsExactlyElementsOf(leaf.chain());
        assertThat(cose.verify(leaf.certificate().getPublicKey(), null)).isTrue();
    }

    @Test
    void taggedCoseSign1Decodes() {
        final CoseSign1 cose = decode(cbor(new CborTag(18, coseSign1(Map.of(1, -7), Map.of(), PAYLOAD, false,
                p256.privateKey()))));
        assertThat(cose.verify(p256.certificate().getPublicKey(), null)).isTrue();
    }

    @Test
    void taggedCoseMac0IsRefused() {
        final byte[] mac0 = cbor(new CborTag(17, coseSign1(Map.of(1, -7), Map.of(), PAYLOAD, false,
                p256.privateKey())));
        assertCode(() -> decode(mac0), WalletErrorCode.INVALID_RESPONSE);
    }

    @Test
    void deviceResponseIssuerAuthAndDeviceSignatureVerify() {
        final TestWallet wallet = TestWallet.create();
        final Instant now = Instant.now();
        final MdocCredential pid = wallet.mdocPid(Map.of("given_name", "Erika", "family_name", "Mustermann"),
                now.minusSeconds(60), now.minusSeconds(60), now.plus(Duration.ofDays(30)), Optional.empty());
        final byte[] transcript = cbor(java.util.Arrays.asList(null, null, List.of("OpenID4VPHandover", new byte[32])));
        final CborValue.Dict response = (CborValue.Dict) StrictCbor.decode(
                TestWallet.mdocDeviceResponse(pid, Set.of("given_name"), transcript));
        final CborValue.Dict document = (CborValue.Dict) ((CborValue.Array) response.get("documents").orElseThrow())
                .items().get(0);
        final CborValue.Dict issuerSigned = (CborValue.Dict) document.get("issuerSigned").orElseThrow();
        final CoseSign1 issuerAuth = CoseSign1.decode(issuerSigned.get("issuerAuth").orElseThrow());

        assertThat(issuerAuth.x5chain()).containsExactlyElementsOf(wallet.issuer().chain());
        assertThat(issuerAuth.verify(issuerAuth.x5chain().get(0).getPublicKey(), null)).isTrue();
        assertThat(issuerAuth.payload()).isEqualTo(pid.mso());

        final CborValue.Dict deviceSigned = (CborValue.Dict) document.get("deviceSigned").orElseThrow();
        final CoseSign1 deviceSignature = CoseSign1.decode(((CborValue.Dict) deviceSigned.get("deviceAuth")
                .orElseThrow()).get("deviceSignature").orElseThrow());
        final byte[] deviceNameSpaces = ((CborValue.Embedded) deviceSigned.get("nameSpaces").orElseThrow()).encoded();
        final ByteArrayOutputStream deviceAuthentication = new ByteArrayOutputStream();
        deviceAuthentication.write(0x84);
        deviceAuthentication.writeBytes(cbor("DeviceAuthentication"));
        deviceAuthentication.writeBytes(transcript);
        deviceAuthentication.writeBytes(cbor(pid.docType()));
        deviceAuthentication.writeBytes(deviceNameSpaces);
        final byte[] detached = cbor(new CborTag(24, deviceAuthentication.toByteArray()));

        assertThat(deviceSignature.payload()).isNull();
        assertThat(deviceSignature.verify(publicKey(pid), detached)).isTrue();
        final byte[] otherTranscript = cbor(java.util.Arrays.asList(null, null, List.of("other")));
        assertThat(deviceSignature.verify(publicKey(pid), cbor(new CborTag(24, otherTranscript)))).isFalse();
    }

    // ------------------------------------------------------------------------------------------- signature

    @Test
    void tamperedPayloadFails() {
        final List<Object> cose = coseSign1(Map.of(1, -7), Map.of(), PAYLOAD, false, p256.privateKey());
        cose.set(2, "mdoc pAyload".getBytes(StandardCharsets.UTF_8));
        assertThat(decode(cbor(cose)).verify(p256.certificate().getPublicKey(), null)).isFalse();
    }

    @Test
    void tamperedSignatureAndWrongKeyFail() {
        final List<Object> cose = coseSign1(Map.of(1, -7), Map.of(), PAYLOAD, false, p256.privateKey());
        final byte[] signature = ((byte[]) cose.get(3)).clone();
        signature[7] ^= 0x01;
        final List<Object> tampered = new ArrayList<>(cose);
        tampered.set(3, signature);
        assertThat(decode(cbor(tampered)).verify(p256.certificate().getPublicKey(), null)).isFalse();

        final Leaf other = pki.issueLeaf(TestPki.LeafSpec.defaults());
        assertThat(decode(cbor(cose)).verify(other.certificate().getPublicKey(), null)).isFalse();
    }

    @Test
    void tamperedProtectedHeaderFails() {
        final List<Object> cose = coseSign1(Map.of(1, -7), Map.of(), PAYLOAD, false, p256.privateKey());
        final Map<Object, Object> changed = new LinkedHashMap<>();
        changed.put(1, -7);
        changed.put(4, "kid".getBytes(StandardCharsets.UTF_8));
        cose.set(0, cbor(changed));
        assertThat(decode(cbor(cose)).verify(p256.certificate().getPublicKey(), null)).isFalse();
    }

    @Test
    void nonPreferredProtectedHeaderIsVerifiedOverTheBytesAsReceived() {
        // {1: -7} with the label written as 18 01 instead of 01: re-encoding it would break the signature
        final byte[] nonPreferred = {(byte) 0xa1, 0x18, 0x01, 0x26};
        final CoseSign1 cose = decode(cbor(TestWallet.coseSign1(nonPreferred, Map.of(), PAYLOAD, false,
                p256.privateKey())));

        assertThat(cose.algorithm()).isEqualTo(-7);
        assertThat(cose.protectedHeader()).isEqualTo(nonPreferred);
        assertThat(cose.verify(p256.certificate().getPublicKey(), null)).isTrue();
    }

    @Test
    void protectedHeaderIsDecodedOnce() {
        final CoseSign1 cose = decode(sign(Map.of(1, -7), Map.of(), PAYLOAD, p256));
        assertThat(cose.protectedParameters()).isSameAs(cose.protectedParameters());
    }

    @ParameterizedTest
    @ValueSource(ints = {0, 63, 65, 128})
    void signatureOfTheWrongLengthIsInvalidNotAnException(final int length) {
        final List<Object> cose = coseSign1(Map.of(1, -7), Map.of(), PAYLOAD, false, p256.privateKey());
        cose.set(3, java.util.Arrays.copyOf((byte[]) cose.get(3), length));
        assertThat(decode(cbor(cose)).verify(p256.certificate().getPublicKey(), null)).isFalse();
    }

    // ------------------------------------------------------------------------------------------- algorithm

    @ParameterizedTest
    @ValueSource(ints = {-257, -37, 0, -8, -9, -47, -51, -52, 5})
    void algorithmOutsideTheAllowListIsRefused(final int alg) {
        final CoseSign1 cose = decode(sign(Map.of(1, alg), Map.of(), PAYLOAD, p256));
        assertThat(cose.algorithm()).isEqualTo(alg);
        assertCode(() -> cose.verify(p256.certificate().getPublicKey(), null), WalletErrorCode.ALGORITHM_NOT_ALLOWED);
    }

    @Test
    void textAlgorithmIsRefused() {
        final CoseSign1 cose = decode(sign(Map.of(1, "ES256"), Map.of(), PAYLOAD, p256));
        assertCode(cose::algorithm, WalletErrorCode.ALGORITHM_NOT_ALLOWED);
        assertCode(() -> cose.verify(p256.certificate().getPublicKey(), null), WalletErrorCode.ALGORITHM_NOT_ALLOWED);
    }

    @Test
    void algorithmOnlyInTheUnprotectedHeaderIsRefused() {
        final CoseSign1 cose = decode(sign(Map.of(), Map.of(1, -7), PAYLOAD, p256));
        assertCode(cose::algorithm, WalletErrorCode.ALGORITHM_NOT_ALLOWED);
        assertCode(() -> cose.verify(p256.certificate().getPublicKey(), null), WalletErrorCode.ALGORITHM_NOT_ALLOWED);
    }

    @Test
    void headerLabelInBothBucketsIsRefused() {
        assertCode(() -> decode(sign(Map.of(1, -7), Map.of(1, -7), PAYLOAD, p256)), WalletErrorCode.INVALID_RESPONSE);
    }

    @Test
    void critHeaderIsRefused() {
        final Map<Object, Object> header = new LinkedHashMap<>();
        header.put(1, -7);
        header.put(2, List.of(99));
        assertCode(() -> decode(sign(header, Map.of(), PAYLOAD, p256)), WalletErrorCode.INVALID_RESPONSE);
        assertCode(() -> decode(sign(Map.of(1, -7), Map.of(2, List.of(99)), PAYLOAD, p256)),
                WalletErrorCode.INVALID_RESPONSE);
    }

    @Test
    void keyWhoseCurveDoesNotMatchTheAlgorithmIsRefused() {
        // ES384 claimed, signed and verified with a P-256 key
        final CoseSign1 es384OnP256 = decode(sign(Map.of(1, -35), Map.of(), PAYLOAD, p256));
        assertCode(() -> es384OnP256.verify(p256.certificate().getPublicKey(), null),
                WalletErrorCode.ALGORITHM_NOT_ALLOWED);
        // ES256 claimed, verified with a P-384 key
        final CoseSign1 es256 = decode(sign(Map.of(1, -7), Map.of(), PAYLOAD, p256));
        assertCode(() -> es256.verify(p384.certificate().getPublicKey(), null), WalletErrorCode.ALGORITHM_NOT_ALLOWED);
    }

    @Test
    void keyOnAnotherCurveOfTheSameSizeIsRefused() throws Exception {
        final KeyPairGenerator gen = KeyPairGenerator.getInstance("EC",
                new org.bouncycastle.jce.provider.BouncyCastleProvider());
        gen.initialize(new java.security.spec.ECGenParameterSpec("brainpoolP256r1"));
        final PublicKey brainpool = gen.generateKeyPair().getPublic();
        final CoseSign1 cose = decode(sign(Map.of(1, -7), Map.of(), PAYLOAD, p256));
        assertCode(() -> cose.verify(brainpool, null), WalletErrorCode.ALGORITHM_NOT_ALLOWED);
    }

    @Test
    void rsaKeyIsRefused() throws Exception {
        final KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(2048);
        final PublicKey rsa = gen.generateKeyPair().getPublic();
        final CoseSign1 cose = decode(sign(Map.of(1, -7), Map.of(), PAYLOAD, p256));
        assertCode(() -> cose.verify(rsa, null), WalletErrorCode.ALGORITHM_NOT_ALLOWED);
    }

    @Test
    void explicitAllowListCanAdmitEsp256ButNotUnknownAlgorithms() {
        final CoseSign1 esp256 = decode(sign(Map.of(1, -9), Map.of(), PAYLOAD, p256));
        assertThat(esp256.verify(p256.certificate().getPublicKey(), null, Set.of(-7, -9))).isTrue();
        final CoseSign1 rs256 = decode(sign(Map.of(1, -257), Map.of(), PAYLOAD, p256));
        assertCode(() -> rs256.verify(p256.certificate().getPublicKey(), null, Set.of(-257)),
                WalletErrorCode.ALGORITHM_NOT_ALLOWED);
    }

    // ------------------------------------------------------------------------------------------- x5chain

    @Test
    void missingX5chainIsIssuerUntrusted() {
        final CoseSign1 cose = decode(sign(Map.of(1, -7), Map.of(), PAYLOAD, p256));
        assertCode(cose::x5chain, WalletErrorCode.ISSUER_UNTRUSTED);
        assertCode(cose::protectedX5chain, WalletErrorCode.ISSUER_UNTRUSTED);
    }

    @Test
    void x5chainIsReadFromEitherBucketAndAsASingleCertificate() throws Exception {
        final Map<Object, Object> protectedHeader = new LinkedHashMap<>();
        protectedHeader.put(1, -7);
        protectedHeader.put(33, p256.certificate().getEncoded()); // a single bstr
        final CoseSign1 inProtected = decode(sign(protectedHeader, Map.of(), PAYLOAD, p256));
        assertThat(inProtected.x5chain()).containsExactly(p256.certificate());
        assertThat(inProtected.protectedX5chain()).containsExactly(p256.certificate());

        final CoseSign1 inUnprotected = decode(sign(Map.of(1, -7), Map.of(33, TestWallet.x5chain(p256.chain())),
                PAYLOAD, p256));
        assertThat(inUnprotected.x5chain()).containsExactlyElementsOf(p256.chain());
        assertCode(inUnprotected::protectedX5chain, WalletErrorCode.ISSUER_UNTRUSTED);
    }

    @Test
    void malformedX5chainIsIssuerUntrusted() {
        for (final Object bad : List.of(new byte[] {0x30, 0x03, 0x01}, List.of(), List.of("not a bstr"), 7)) {
            final CoseSign1 cose = decode(sign(Map.of(1, -7), Map.of(33, bad), PAYLOAD, p256));
            assertCode(cose::x5chain, WalletErrorCode.ISSUER_UNTRUSTED);
        }
    }

    // ------------------------------------------------------------------------------------------- detached

    @Test
    void detachedPayloadVerifies() {
        final CoseSign1 cose = decode(cbor(coseSign1(Map.of(1, -7), Map.of(), PAYLOAD, true, p256.privateKey())));
        assertThat(cose.payload()).isNull();
        assertThat(cose.verify(p256.certificate().getPublicKey(), PAYLOAD)).isTrue();
        assertThat(cose.verify(p256.certificate().getPublicKey(), "other".getBytes(StandardCharsets.UTF_8)))
                .isFalse();
        assertCode(() -> cose.verify(p256.certificate().getPublicKey(), null), WalletErrorCode.INVALID_RESPONSE);
    }

    @Test
    void attachedPayloadWithADetachedOneIsRefused() {
        final CoseSign1 cose = decode(sign(Map.of(1, -7), Map.of(), PAYLOAD, p256));
        assertCode(() -> cose.verify(p256.certificate().getPublicKey(), PAYLOAD), WalletErrorCode.INVALID_RESPONSE);
    }

    // ------------------------------------------------------------------------------------------- structure

    @Test
    void malformedStructuresAreInvalidResponse() {
        final List<Object> good = coseSign1(Map.of(1, -7), Map.of(), PAYLOAD, false, p256.privateKey());
        final List<List<Object>> bad = new ArrayList<>();
        bad.add(good.subList(0, 3));
        final List<Object> five = new ArrayList<>(good);
        five.add(new byte[0]);
        bad.add(five);
        bad.add(replace(good, 0, Map.of(1, -7)));          // protected header as a map, not a bstr
        bad.add(replace(good, 0, cbor(List.of(1, -7))));   // protected bstr that is not a map
        bad.add(replace(good, 1, new byte[0]));            // unprotected header not a map
        bad.add(replace(good, 2, "text payload"));         // payload not bstr / nil
        bad.add(replace(good, 3, "text signature"));       // signature not a bstr
        for (final List<Object> cose : bad) {
            assertCode(() -> decode(cbor(cose)), WalletErrorCode.INVALID_RESPONSE);
        }
        assertCode(() -> CoseSign1.decode(new CborValue.Text("x")), WalletErrorCode.INVALID_RESPONSE);
        assertCode(() -> CoseSign1.decode(null), WalletErrorCode.INVALID_RESPONSE);
    }

    @Test
    void emptyProtectedHeaderIsAnEmptyMap() {
        final CoseSign1 cose = decode(sign(Map.of(), Map.of(), PAYLOAD, p256));
        assertThat(cose.protectedHeader()).isEmpty();
        assertThat(cose.protectedParameters().entries()).isEmpty();
    }

    @Test
    void accessorsReturnCopies() {
        final CoseSign1 cose = decode(sign(Map.of(1, -7), Map.of(), PAYLOAD, p256));
        cose.payload()[0] ^= 1;
        cose.signature()[0] ^= 1;
        cose.protectedHeader()[0] ^= 1;
        assertThat(cose.verify(p256.certificate().getPublicKey(), null)).isTrue();
        assertThat(cose.toString()).doesNotContain("mdoc payload");
    }

    // ------------------------------------------------------------------------------------------- helpers

    private static byte[] sign(final Map<Object, Object> protectedHeader, final Map<Object, Object> unprotected,
            final byte[] payload, final Leaf leaf) {
        return cbor(coseSign1(protectedHeader, unprotected, payload, false, leaf.privateKey()));
    }

    private static CoseSign1 decode(final byte[] encoded) {
        return CoseSign1.decode(StrictCbor.decode(encoded));
    }

    private static List<Object> replace(final List<Object> list, final int index, final Object value) {
        final List<Object> copy = new ArrayList<>(list);
        copy.set(index, value);
        return copy;
    }

    private static PublicKey publicKey(final MdocCredential pid) {
        try {
            return pid.deviceKey().toECPublicKey();
        } catch (final com.nimbusds.jose.JOSEException e) {
            throw new IllegalStateException(e);
        }
    }

    private static void assertCode(final ThrowingCallable call, final WalletErrorCode code) {
        assertThatThrownBy(call).isInstanceOfSatisfying(WalletVerificationException.class,
                e -> assertThat(e.code()).isEqualTo(code));
    }

    @Test
    void customCborLimitsAreHonouredForTheProtectedHeader() {
        final Map<Object, Object> header = new LinkedHashMap<>();
        header.put(1, -7);
        header.put(4, new byte[32]); // kid: a 38-byte protected header
        final CborValue message = StrictCbor.decode(sign(header, Map.of(), PAYLOAD, p256));

        assertThat(CoseSign1.decode(message, CborLimits.DEFAULTS).algorithm()).isEqualTo(-7);
        assertCode(() -> CoseSign1.decode(message, new CborLimits(16, 10_000, 16)), WalletErrorCode.LIMIT_EXCEEDED);
    }
}
