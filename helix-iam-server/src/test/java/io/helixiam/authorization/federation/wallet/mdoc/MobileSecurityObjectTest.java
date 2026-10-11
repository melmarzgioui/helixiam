/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.wallet.mdoc;

import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import io.helixiam.authorization.federation.wallet.WalletErrorCode;
import io.helixiam.authorization.federation.wallet.WalletVerificationException;
import io.helixiam.authorization.federation.wallet.status.StatusReference;
import io.helixiam.authorization.federation.wallet.testwallet.TestWallet;
import io.helixiam.authorization.federation.wallet.testwallet.TestWallet.CborTag;
import io.helixiam.authorization.federation.wallet.testwallet.TestWallet.MdocCredential;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Consumer;

import static io.helixiam.authorization.federation.wallet.testwallet.TestWallet.cbor;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * {@link MobileSecurityObject#decode}: the tag-24 MobileSecurityObjectBytes of a {@link TestWallet} PID, and one
 * broken member at a time (digest algorithm allow-list, COSE_Key, tdate validity, status reference, digests).
 */
class MobileSecurityObjectTest {

    private static final Instant SIGNED = Instant.now().minus(Duration.ofHours(1)).truncatedTo(ChronoUnit.SECONDS);
    private static final Instant VALID_UNTIL = SIGNED.plus(Duration.ofDays(90));
    private static final String NS = TestWallet.MDOC_PID_DOCTYPE;

    private static TestWallet wallet;

    @BeforeAll
    static void wallet() {
        wallet = TestWallet.create();
    }

    @Test
    void testWalletPidDecodes() throws Exception {
        final Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("family_name", "Mustermann");
        claims.put("given_name", "Erika");
        claims.put("birth_date", new CborTag(1004, "1964-08-12"));
        final MdocCredential pid = wallet.mdocPid(claims, SIGNED, SIGNED, VALID_UNTIL, Optional.empty());

        final MobileSecurityObject mso = MobileSecurityObject.decode(pid.mso());

        assertThat(mso.version()).isEqualTo("1.0");
        assertThat(mso.docType()).isEqualTo(NS);
        assertThat(mso.digestAlgorithm()).isEqualTo("SHA-256");
        assertThat(mso.signed()).isEqualTo(SIGNED);
        assertThat(mso.validFrom()).isEqualTo(SIGNED);
        assertThat(mso.validUntil()).isEqualTo(VALID_UNTIL);
        assertThat(mso.status()).isNull();
        assertThat(mso.deviceKey()).isEqualTo(pid.deviceKey().toECPublicKey());
        assertThat(mso.valueDigests()).containsOnlyKeys(NS);
        assertThat(mso.valueDigests().get(NS)).containsOnlyKeys(0, 1, 2);
        assertThat(mso.valueDigests().get(NS).get(1))
                .isEqualTo(TestWallet.sha("SHA-256", pid.itemBytes("given_name")));
    }

    @Test
    void msoOfAVerifiedIssuerAuthDecodes() {
        final MdocCredential pid = wallet.mdocPid(Map.of("given_name", "Erika"), SIGNED, SIGNED, VALID_UNTIL,
                Optional.empty());
        final CoseSign1 issuerAuth = CoseSign1.decode(StrictCbor.decode(pid.issuerAuthBytes()));
        assertThat(issuerAuth.verify(wallet.issuer().certificate().getPublicKey(), null)).isTrue();
        assertThat(MobileSecurityObject.decode(issuerAuth.payload()).docType()).isEqualTo(NS);
    }

    @Test
    void statusListReferenceIsRead() {
        final MdocCredential pid = wallet.mdocPid(Map.of("given_name", "Erika"), SIGNED, SIGNED, VALID_UNTIL,
                Optional.of(new StatusReference(412, "https://status.example/lists/7")));
        assertThat(MobileSecurityObject.decode(pid.mso()).status())
                .isInstanceOfSatisfying(MobileSecurityObject.StatusList.class, s -> {
                    assertThat(s.reference()).isEqualTo(new StatusReference(412, "https://status.example/lists/7"));
                    assertThat(s.certificate()).isNull();
                });
    }

    @Test
    void statusListWithACertificateIsRead() {
        final Map<Object, Object> list = new LinkedHashMap<>();
        list.put("idx", 3);
        list.put("uri", "https://status.example/1");
        list.put("certificate", new byte[] {1, 2, 3});
        assertThat(decode(mso -> mso.put("status", Map.of("status_list", list))).status())
                .isInstanceOfSatisfying(MobileSecurityObject.StatusList.class, s -> {
                    assertThat(s.reference()).isEqualTo(new StatusReference(3, "https://status.example/1"));
                    assertThat(s.certificate()).containsExactly(1, 2, 3); // kept for the ISO trust point, not used
                });
    }

    @Test
    void statusWithoutAStatusListIsPresentButNotEvaluable() {
        final Map<Object, Object> identifierList = Map.of("id", new byte[] {1}, "uri", "https://status.example/ids");
        assertThat(decode(mso -> mso.put("status", Map.of("identifier_list", identifierList))).status())
                .isInstanceOfSatisfying(MobileSecurityObject.NotEvaluable.class,
                        s -> assertThat(s.mechanisms()).containsExactly("identifier_list"));
        assertThat(decode(mso -> mso.put("status", Map.of())).status())
                .isInstanceOfSatisfying(MobileSecurityObject.NotEvaluable.class,
                        s -> assertThat(s.mechanisms()).isEmpty());
    }

    @Test
    void statusListWinsNextToAnIdentifierList() {
        final Map<Object, Object> status = new LinkedHashMap<>();
        status.put("identifier_list", Map.of("id", new byte[] {1}, "uri", "https://status.example/ids"));
        status.put("status_list", Map.of("idx", 1, "uri", "https://status.example/1"));
        assertThat(decode(mso -> mso.put("status", status)).status())
                .isInstanceOf(MobileSecurityObject.StatusList.class);
    }

    @Test
    void validP384And521DeviceKeysDecode() throws Exception {
        for (final Curve curve : List.of(Curve.P_384, Curve.P_521)) {
            final ECKey key = TestWallet.ecKey(curve);
            final MobileSecurityObject mso = decode(m -> m.put("deviceKeyInfo",
                    Map.of("deviceKey", TestWallet.coseKey(key))));
            assertThat(mso.deviceKey()).isEqualTo(key.toECPublicKey());
        }
    }

    // ------------------------------------------------------------------------------------------- digest algorithm

    @ParameterizedTest
    @ValueSource(strings = {"SHA-384", "SHA-512"})
    void otherAllowedDigestAlgorithmsDecode(final String alg) {
        final int length = alg.equals("SHA-384") ? 48 : 64;
        final MobileSecurityObject mso = decode(m -> {
            m.put("digestAlgorithm", alg);
            m.put("valueDigests", Map.of(NS, Map.of(0, new byte[length])));
        });
        assertThat(mso.digestAlgorithm()).isEqualTo(alg);
    }

    @ParameterizedTest
    @ValueSource(strings = {"SHA-1", "MD5", "sha-256", "SHA256", "SHA3-256", ""})
    void digestAlgorithmOutsideTheAllowListIsRefused(final String alg) {
        assertCode(mso -> mso.put("digestAlgorithm", alg), WalletErrorCode.ALGORITHM_NOT_ALLOWED);
    }

    @Test
    void digestOfTheWrongLengthIsInvalid() {
        assertCode(mso -> mso.put("valueDigests", Map.of(NS, Map.of(0, new byte[31]))),
                WalletErrorCode.INVALID_RESPONSE);
    }

    @Test
    void malformedValueDigestsAreInvalid() {
        assertCode(mso -> mso.put("valueDigests", Map.of(NS, Map.of(-1, new byte[32]))),
                WalletErrorCode.INVALID_RESPONSE);
        assertCode(mso -> mso.put("valueDigests", Map.of(NS, Map.of(1L << 31, new byte[32]))),
                WalletErrorCode.INVALID_RESPONSE);
        assertCode(mso -> mso.put("valueDigests", Map.of(NS, Map.of("0", new byte[32]))),
                WalletErrorCode.INVALID_RESPONSE);
        assertCode(mso -> mso.put("valueDigests", Map.of(7, Map.of(0, new byte[32]))),
                WalletErrorCode.INVALID_RESPONSE);
        assertCode(mso -> mso.put("valueDigests", Map.of(NS, List.of(new byte[32]))),
                WalletErrorCode.INVALID_RESPONSE);
        assertCode(mso -> mso.put("valueDigests", Map.of(NS, Map.of(0, "digest"))),
                WalletErrorCode.INVALID_RESPONSE);
    }

    // ------------------------------------------------------------------------------------------- COSE_Key

    @Test
    void coseKeyWithACurveMismatchIsInvalid() {
        // crv 2 (P-384) with P-256 coordinates
        assertCode(mso -> deviceKey(mso).put(-1, 2), WalletErrorCode.INVALID_RESPONSE);
        // crv 1 (P-256) with P-384 coordinates
        final Map<Object, Object> p384 = TestWallet.coseKey(TestWallet.ecKey(Curve.P_384));
        p384.put(-1, 1);
        assertCode(mso -> mso.put("deviceKeyInfo", Map.of("deviceKey", p384)), WalletErrorCode.INVALID_RESPONSE);
    }

    @Test
    void coseKeyPointNotOnTheCurveIsInvalid() {
        assertCode(mso -> {
            final byte[] y = ((byte[]) deviceKey(mso).get(-3)).clone();
            y[31] ^= 0x01;
            deviceKey(mso).put(-3, y);
        }, WalletErrorCode.INVALID_RESPONSE);
    }

    @Test
    void unsupportedOrMalformedCoseKeysAreInvalid() {
        assertCode(mso -> deviceKey(mso).put(1, 1), WalletErrorCode.INVALID_RESPONSE);        // kty OKP
        assertCode(mso -> deviceKey(mso).put(1, 3), WalletErrorCode.INVALID_RESPONSE);        // kty RSA
        assertCode(mso -> deviceKey(mso).put(-1, 8), WalletErrorCode.INVALID_RESPONSE);       // crv brainpool/unknown
        assertCode(mso -> deviceKey(mso).put(-3, true), WalletErrorCode.INVALID_RESPONSE);    // compressed point
        assertCode(mso -> deviceKey(mso).remove(-2), WalletErrorCode.INVALID_RESPONSE);       // no x
        assertCode(mso -> deviceKey(mso).put(-4, new byte[32]), WalletErrorCode.INVALID_RESPONSE); // private d
        assertCode(mso -> deviceKey(mso).put(-2, new byte[33]), WalletErrorCode.INVALID_RESPONSE); // x too long
        assertCode(mso -> mso.put("deviceKeyInfo", Map.of()), WalletErrorCode.INVALID_RESPONSE);
        assertCode(mso -> mso.remove("deviceKeyInfo"), WalletErrorCode.INVALID_RESPONSE);
    }

    // ------------------------------------------------------------------------------------------- validity

    @Test
    void validityMustBeTdate() {
        assertCode(mso -> validity(mso).put("validUntil", new CborTag(1004, "2030-01-01")),
                WalletErrorCode.INVALID_RESPONSE);
        assertCode(mso -> validity(mso).put("validUntil", "2030-01-01T00:00:00Z"), WalletErrorCode.INVALID_RESPONSE);
        assertCode(mso -> validity(mso).put("signed", VALID_UNTIL.getEpochSecond()), WalletErrorCode.INVALID_RESPONSE);
        assertCode(mso -> validity(mso).put("signed", new CborTag(1, VALID_UNTIL.getEpochSecond())),
                WalletErrorCode.INVALID_RESPONSE);
        assertCode(mso -> validity(mso).put("validFrom", new CborTag(0, "yesterday")),
                WalletErrorCode.INVALID_RESPONSE);
        assertCode(mso -> validity(mso).remove("validFrom"), WalletErrorCode.INVALID_RESPONSE);
    }

    @Test
    void expectedUpdateMustAlsoBeTdate() {
        assertThat(decode(mso -> validity(mso).put("expectedUpdate", TestWallet.tdate(VALID_UNTIL))).docType())
                .isEqualTo(NS);
        assertCode(mso -> validity(mso).put("expectedUpdate", "soon"), WalletErrorCode.INVALID_RESPONSE);
    }

    @Test
    void inconsistentValidityIsInvalid() {
        assertCode(mso -> validity(mso).put("validUntil", TestWallet.tdate(SIGNED)), WalletErrorCode.INVALID_RESPONSE);
        assertCode(mso -> validity(mso).put("validFrom", TestWallet.tdate(SIGNED.minusSeconds(1))),
                WalletErrorCode.INVALID_RESPONSE);
    }

    @Test
    void tdateWithAnOffsetIsNormalisedToAnInstant() {
        final MobileSecurityObject mso = decode(m -> validity(m).put("validUntil",
                new CborTag(0, "2099-01-01T02:00:00+02:00")));
        assertThat(mso.validUntil()).isEqualTo(Instant.parse("2099-01-01T00:00:00Z"));
    }

    // ------------------------------------------------------------------------------------------- status

    @Test
    void malformedStatusIsInvalidNeverNull() {
        assertCode(mso -> mso.put("status", "revoked"), WalletErrorCode.INVALID_RESPONSE);
        assertCode(mso -> mso.put("status", Map.of("identifier_list", "x")), WalletErrorCode.INVALID_RESPONSE);
        assertCode(mso -> mso.put("status", Map.of("identifier_list",
                Map.of("id", "1", "uri", "https://status.example/ids"))), WalletErrorCode.INVALID_RESPONSE);
        assertCode(mso -> mso.put("status", Map.of("identifier_list", Map.of("id", new byte[] {1}))),
                WalletErrorCode.INVALID_RESPONSE);
        assertCode(mso -> mso.put("status", Map.of("identifier_list",
                Map.of("id", new byte[] {1}, "uri", "https://s.example", "certificate", "pem"))),
                WalletErrorCode.INVALID_RESPONSE);
        assertCode(mso -> mso.put("status", Map.of("status_list", "x")), WalletErrorCode.INVALID_RESPONSE);
        assertCode(mso -> mso.put("status", Map.of("status_list", Map.of("idx", -1, "uri", "https://s.example"))),
                WalletErrorCode.INVALID_RESPONSE);
        assertCode(mso -> mso.put("status", Map.of("status_list", Map.of("idx", 1L << 31, "uri", "https://s.example"))),
                WalletErrorCode.INVALID_RESPONSE);
        assertCode(mso -> mso.put("status", Map.of("status_list", Map.of("idx", "1", "uri", "https://s.example"))),
                WalletErrorCode.INVALID_RESPONSE);
        assertCode(mso -> mso.put("status", Map.of("status_list", Map.of("idx", 1))), WalletErrorCode.INVALID_RESPONSE);
        assertCode(mso -> mso.put("status", Map.of("status_list", Map.of("idx", 1, "uri", " "))),
                WalletErrorCode.INVALID_RESPONSE);
        assertCode(mso -> mso.put("status", Map.of("status_list",
                Map.of("idx", 1, "uri", "https://s.example", "certificate", "pem"))), WalletErrorCode.INVALID_RESPONSE);
    }

    // ------------------------------------------------------------------------------------------- structure

    @Test
    void missingOrMistypedMembersAreInvalid() {
        for (final String member : List.of("version", "digestAlgorithm", "valueDigests", "docType", "validityInfo")) {
            assertCode(mso -> mso.remove(member), WalletErrorCode.INVALID_RESPONSE);
        }
        assertCode(mso -> mso.put("docType", 7), WalletErrorCode.INVALID_RESPONSE);
        assertCode(mso -> mso.put("docType", ""), WalletErrorCode.INVALID_RESPONSE);
        assertCode(mso -> mso.put("version", List.of()), WalletErrorCode.INVALID_RESPONSE);
        assertCode(mso -> mso.put("validityInfo", List.of()), WalletErrorCode.INVALID_RESPONSE);
    }

    @Test
    void payloadMustBeTag24WrappingAMap() {
        final byte[] untagged = cbor(baseMso());
        assertCode(() -> MobileSecurityObject.decode(untagged), WalletErrorCode.INVALID_RESPONSE);
        assertCode(() -> MobileSecurityObject.decode(cbor(new CborTag(24, cbor(List.of(1))))),
                WalletErrorCode.INVALID_RESPONSE);
        assertCode(() -> MobileSecurityObject.decode(cbor(new CborTag(24, new byte[] {(byte) 0xff}))),
                WalletErrorCode.INVALID_RESPONSE);
        assertCode(() -> MobileSecurityObject.decode(new byte[0]), WalletErrorCode.INVALID_RESPONSE);
        assertCode(() -> MobileSecurityObject.decode(null), WalletErrorCode.INVALID_RESPONSE);
    }

    @Test
    void depthBombIsLimitExceeded() {
        final byte[] bomb = new byte[40];
        Arrays.fill(bomb, (byte) 0x81); // array(1) nested 39 times
        bomb[39] = 0x00;
        assertCode(() -> MobileSecurityObject.decode(cbor(new CborTag(24, bomb))), WalletErrorCode.LIMIT_EXCEEDED);
    }

    @Test
    void valueDigestsAreImmutableCopies() {
        final MobileSecurityObject mso = decode(m -> { });
        final byte[] digest = mso.valueDigests().get(NS).get(0);
        digest[0] ^= 1;
        assertThat(mso.valueDigests().get(NS).get(0)).isNotEqualTo(digest);
        assertThatThrownBy(() -> mso.valueDigests().put("x", Map.of())).isInstanceOf(UnsupportedOperationException.class);
    }

    // ------------------------------------------------------------------------------------------- helpers

    /** A valid MSO map with one SHA-256 digest and a fresh P-256 device key. */
    private static Map<Object, Object> baseMso() {
        final Map<Object, Object> digests = new LinkedHashMap<>();
        digests.put(0, new byte[32]);
        final Map<String, Map<Object, Object>> valueDigests = new LinkedHashMap<>();
        valueDigests.put(NS, digests);
        return TestWallet.mso(NS, "SHA-256", valueDigests, TestWallet.coseKey(TestWallet.ecKey(Curve.P_256)), SIGNED,
                SIGNED, VALID_UNTIL);
    }

    private static MobileSecurityObject decode(final Consumer<Map<Object, Object>> change) {
        final Map<Object, Object> mso = baseMso();
        change.accept(mso);
        return MobileSecurityObject.decode(cbor(new CborTag(24, cbor(mso))));
    }

    @SuppressWarnings("unchecked")
    private static Map<Object, Object> deviceKey(final Map<Object, Object> mso) {
        return (Map<Object, Object>) ((Map<Object, Object>) mso.get("deviceKeyInfo")).get("deviceKey");
    }

    @SuppressWarnings("unchecked")
    private static Map<Object, Object> validity(final Map<Object, Object> mso) {
        return (Map<Object, Object>) mso.get("validityInfo");
    }

    private static void assertCode(final Consumer<Map<Object, Object>> change, final WalletErrorCode code) {
        assertCode(() -> decode(change), code);
    }

    private static void assertCode(final ThrowingCallable call, final WalletErrorCode code) {
        assertThatThrownBy(call).isInstanceOfSatisfying(WalletVerificationException.class,
                e -> assertThat(e.code()).isEqualTo(code));
    }

    @Test
    void customCborLimitsAreHonoured() {
        final MdocCredential pid = wallet.mdocPid(Map.of("given_name", "Erika", "family_name", "Mustermann",
                "nationality", "DE"), SIGNED, SIGNED, VALID_UNTIL, Optional.empty());

        assertThat(MobileSecurityObject.decode(pid.mso(), CborLimits.DEFAULTS).docType()).isEqualTo(NS);
        assertCode(() -> MobileSecurityObject.decode(pid.mso(), new CborLimits(16, 10, 256 * 1024)),
                WalletErrorCode.LIMIT_EXCEEDED);
        assertCode(() -> MobileSecurityObject.decode(pid.mso(), new CborLimits(2, 10_000, 256 * 1024)),
                WalletErrorCode.LIMIT_EXCEEDED);
    }
}
