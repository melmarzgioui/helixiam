/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.wallet.status;

import io.helixiam.authorization.federation.wallet.WalletErrorCode;
import io.helixiam.authorization.federation.wallet.WalletVerificationException;
import io.helixiam.authorization.federation.wallet.testwallet.TestPki;
import io.helixiam.authorization.federation.wallet.testwallet.TestPki.KeyType;
import io.helixiam.authorization.federation.wallet.testwallet.TestPki.Leaf;
import io.helixiam.authorization.federation.wallet.testwallet.TestWallet;
import io.helixiam.authorization.federation.wallet.testwallet.TestWallet.CborTag;
import io.helixiam.authorization.federation.wallet.trust.IssuerTrustValidator;
import io.helixiam.authorization.federation.wallet.trust.TrustAnchors;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static io.helixiam.authorization.federation.wallet.testwallet.TestWallet.cbor;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * {@link StatusListToken#fromCwt} COSE_Sign1 handling, pinned before and after it moved into
 * {@code mdoc.CoseSign1}: the CWT alg allow-list (ES256 -7 / ESP256 -9, ES384 -35, ES512 -36), COSE_Mac0 and untagged
 * messages refused, x5chain from the protected header only, the key/alg fit and the signature length. CWTs are built
 * with {@link TestWallet}'s CBOR writer.
 */
class StatusListTokenCwtTest {

    private static final String SUB = "https://status.example/lists/1";

    private static TestPki pki;
    private static TrustAnchors anchors;
    private static Leaf p256;
    private static Leaf p384;
    private static final IssuerTrustValidator TRUST = new IssuerTrustValidator();

    @BeforeAll
    static void pki() {
        pki = TestPki.create();
        anchors = pki.trustAnchors(TrustAnchors.RevocationMode.OFF);
        p256 = pki.issueLeaf(TestPki.LeafSpec.defaults());
        p384 = pki.issueLeaf(TestPki.LeafSpec.defaults().withKeyType(KeyType.EC_P384));
    }

    @ParameterizedTest
    @ValueSource(ints = {-7, -9})
    void es256AndEsp256AreAccepted(final int alg) {
        final StatusListToken token = StatusListToken.fromCwt(cwt(alg, p256, true), anchors, Instant.now(), TRUST);
        assertThat(token.subject()).isEqualTo(SUB);
        assertThat(token.statusAt(1)).isEqualTo(1);
        assertThat(token.statusAt(0)).isEqualTo(0);
    }

    @Test
    void es384IsAccepted() {
        assertThat(StatusListToken.fromCwt(cwt(-35, p384, true), anchors, Instant.now(), TRUST).bits()).isEqualTo(1);
    }

    @ParameterizedTest
    @ValueSource(ints = {-257, -8, 0, -37})
    void otherAlgorithmsAreNotAllowed(final int alg) {
        assertCode(() -> StatusListToken.fromCwt(cwt(alg, p256, true), anchors, Instant.now(), TRUST),
                WalletErrorCode.ALGORITHM_NOT_ALLOWED);
    }

    @Test
    void algorithmThatDoesNotFitTheKeyIsNotAllowed() {
        assertCode(() -> StatusListToken.fromCwt(cwt(-35, p256, true), anchors, Instant.now(), TRUST),
                WalletErrorCode.ALGORITHM_NOT_ALLOWED);
    }

    @Test
    void coseMac0AndUntaggedAreInvalid() {
        assertCode(() -> StatusListToken.fromCwt(cbor(new CborTag(17, structure(-7, p256, true))), anchors,
                Instant.now(), TRUST), WalletErrorCode.INVALID_RESPONSE);
        assertCode(() -> StatusListToken.fromCwt(cbor(structure(-7, p256, true)), anchors, Instant.now(), TRUST),
                WalletErrorCode.INVALID_RESPONSE);
    }

    @Test
    void x5chainOnlyUnprotectedIsUntrusted() {
        assertCode(() -> StatusListToken.fromCwt(cwt(-7, p256, false), anchors, Instant.now(), TRUST),
                WalletErrorCode.ISSUER_UNTRUSTED);
    }

    @Test
    void wrongSignatureLengthAndTamperingAreSignatureInvalid() {
        final List<Object> shortSig = structure(-7, p256, true);
        shortSig.set(3, new byte[63]);
        assertCode(() -> StatusListToken.fromCwt(cbor(new CborTag(18, shortSig)), anchors, Instant.now(), TRUST),
                WalletErrorCode.ISSUER_SIGNATURE_INVALID);
        final List<Object> tampered = structure(-7, p256, true);
        final byte[] sig = ((byte[]) tampered.get(3)).clone();
        sig[3] ^= 1;
        tampered.set(3, sig);
        assertCode(() -> StatusListToken.fromCwt(cbor(new CborTag(18, tampered)), anchors, Instant.now(), TRUST),
                WalletErrorCode.ISSUER_SIGNATURE_INVALID);
    }

    @Test
    void detachedPayloadIsInvalid() {
        final List<Object> detached = structure(-7, p256, true);
        detached.set(2, null);
        assertCode(() -> StatusListToken.fromCwt(cbor(new CborTag(18, detached)), anchors, Instant.now(), TRUST),
                WalletErrorCode.INVALID_RESPONSE);
    }

    @Test
    void wrongTypeIsUnsupportedFormat() {
        final Map<Object, Object> header = header(-7, p256, true);
        header.put(16, "application/cwt");
        final List<Object> cose = TestWallet.coseSign1(header, Map.of(), payload(), false, p256.privateKey());
        assertCode(() -> StatusListToken.fromCwt(cbor(new CborTag(18, cose)), anchors, Instant.now(), TRUST),
                WalletErrorCode.UNSUPPORTED_FORMAT);
    }

    // ------------------------------------------------------------------------------------------- helpers

    private static byte[] cwt(final int alg, final Leaf leaf, final boolean protectedX5chain) {
        return cbor(new CborTag(18, structure(alg, leaf, protectedX5chain)));
    }

    private static List<Object> structure(final int alg, final Leaf leaf, final boolean protectedX5chain) {
        final Map<Object, Object> unprotected = new LinkedHashMap<>();
        if (!protectedX5chain) {
            unprotected.put(33, TestWallet.x5chain(leaf.chain()));
        }
        return new ArrayList<>(TestWallet.coseSign1(header(alg, leaf, protectedX5chain), unprotected, payload(),
                false, leaf.privateKey()));
    }

    private static Map<Object, Object> header(final int alg, final Leaf leaf, final boolean protectedX5chain) {
        final Map<Object, Object> header = new LinkedHashMap<>();
        header.put(1, alg);
        header.put(16, "application/statuslist+cwt");
        if (protectedX5chain) {
            header.put(33, TestWallet.x5chain(leaf.chain()));
        }
        return header;
    }

    private static byte[] payload() {
        final Map<Object, Object> statusList = new LinkedHashMap<>();
        statusList.put("bits", 1);
        statusList.put("lst", TokenStatusListClientTest.zlib(new byte[] {0x02}));
        final Map<Object, Object> claims = new LinkedHashMap<>();
        claims.put(2, SUB);
        claims.put(6, Instant.now().minusSeconds(10).getEpochSecond());
        claims.put(4, Instant.now().plusSeconds(3600).getEpochSecond());
        claims.put(65533, statusList);
        return cbor(claims);
    }

    private static void assertCode(final ThrowingCallable call, final WalletErrorCode code) {
        assertThatThrownBy(call).isInstanceOfSatisfying(WalletVerificationException.class,
                e -> assertThat(e.code()).isEqualTo(code));
    }
}
