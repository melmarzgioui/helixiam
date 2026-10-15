/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.wallet.sdjwt;

import tools.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.SignedJWT;
import io.helixiam.authorization.federation.wallet.WalletErrorCode;
import io.helixiam.authorization.federation.wallet.WalletVerificationException;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static io.helixiam.authorization.federation.wallet.sdjwt.SdJwtTest.expected;
import static io.helixiam.authorization.federation.wallet.sdjwt.SdJwtTest.vector;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Disclosure processing per RFC 9901 §7.1 step 3–5 (quoted in docs/eudi-wallet-spec-notes.md §3.6). Positive cases
 * use the RFC 9901 vectors and compare against the RFC's documented "Processed SD-JWT Payload"; negative cases are
 * built here from RFC-shaped disclosures.
 */
class SdJwtDisclosuresTest {

    private static final ObjectMapper JSON = new ObjectMapper();

    /** RFC 9901 §5.1 disclosures, by claim. */
    private static final String FAMILY_NAME = "WyJlbHVWNU9nM2dTTklJOEVZbnN4QV9BIiwgImZhbWlseV9uYW1lIiwgIkRvZSJd";
    private static final String GIVEN_NAME = "WyIyR0xDNDJzS1F2ZUNmR2ZyeU5STjl3IiwgImdpdmVuX25hbWUiLCAiSm9obiJd";
    private static final String EMAIL = "WyI2SWo3dE0tYTVpVlBHYm9TNXRtdlZBIiwgImVtYWlsIiwgImpvaG5kb2VAZXhhbXBsZS5jb20iXQ";
    private static final String NATIONALITY_US = "WyJsa2x4RjVqTVlsR1RQVW92TU5JdkNBIiwgIlVTIl0";

    // ---------------------------------------------------------------- helpers

    private static Map<String, Object> issuerPayload(SdJwt sdJwt) {
        try {
            return SignedJWT.parse(sdJwt.issuerJwt()).getPayload().toJSONObject();
        } catch (java.text.ParseException e) {
            throw new IllegalStateException(e);
        }
    }

    private static Map<String, Object> resolveVector(String file) {
        SdJwt sdJwt = SdJwt.parse(vector(file), 100, 64 * 1024);
        return SdJwtDisclosures.resolve(issuerPayload(sdJwt), sdJwt.disclosures(), "sha-256");
    }

    /** Builds a disclosure exactly as RFC 9901 §4.2.1/§4.2.2: base64url(UTF-8(JSON array)). */
    private static String disclosure(Object... elements) {
        try {
            return b64(JSON.writeValueAsString(List.of(elements)));
        } catch (tools.jackson.core.JacksonException e) {
            throw new IllegalStateException(e);
        }
    }

    private static String b64(String s) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(s.getBytes(StandardCharsets.UTF_8));
    }

    private static String sha256(String d) {
        return SdJwtDisclosures.digest(d, "sha-256");
    }

    private static Map<String, Object> obj(Object... kv) {
        Map<String, Object> m = new LinkedHashMap<>();
        for (int i = 0; i < kv.length; i += 2) {
            m.put((String) kv[i], kv[i + 1]);
        }
        return m;
    }

    private static void assertCode(Runnable r, WalletErrorCode code) {
        assertThatThrownBy(r::run).isInstanceOf(WalletVerificationException.class)
                .satisfies(e -> assertThat(((WalletVerificationException) e).code()).isEqualTo(code));
    }

    private static void assertInvalid(Map<String, Object> payload, List<String> disclosures) {
        assertCode(() -> SdJwtDisclosures.resolve(payload, disclosures, "sha-256"), WalletErrorCode.DISCLOSURE_INVALID);
    }

    // ---------------------------------------------------------------- digest

    @Test
    void digestMatchesRfc9901Section4_2_3Example() {
        assertThat(SdJwtDisclosures.digest(
                "WyJfMjZiYzRMVC1hYzZxMktJNmNCVzVlcyIsICJmYW1pbHlfbmFtZSIsICJNw7ZiaXVzIl0", "sha-256"))
                .isEqualTo("X9yH0Ajrdm1Oij4tWso9UzzKJvPoDxwmuEcO3XAdRC0");
    }

    @Test
    void digestRejectsAlgorithmsOutsideTheAllowList() {
        assertCode(() -> SdJwtDisclosures.digest(FAMILY_NAME, "md5"), WalletErrorCode.ALGORITHM_NOT_ALLOWED);
        assertCode(() -> SdJwtDisclosures.digest(FAMILY_NAME, "SHA-256"), WalletErrorCode.ALGORITHM_NOT_ALLOWED);
        assertCode(() -> SdJwtDisclosures.digest(FAMILY_NAME, null), WalletErrorCode.ALGORITHM_NOT_ALLOWED);
    }

    // ---------------------------------------------------------------- positive: RFC vectors

    @Test
    void rfc9901_5_2_resolvesToTheDocumentedProcessedPayload() {
        // object properties, an object-valued claim (address) and an array element (nationalities, one decoy removed)
        assertThat(resolveVector("rfc9901-5.2-sd-jwt-kb.txt"))
                .isEqualTo(expected("rfc9901-5.2-expected.json").get("processed_payload"));
    }

    @Test
    void rfc9901_A3_recursiveDisclosureResolvesToTheDocumentedProcessedPayload() {
        // age_equal_or_over is itself a disclosure whose value carries an _sd with the "18" disclosure
        assertThat(resolveVector("rfc9901-A.3-sd-jwt-vc-kb.txt"))
                .isEqualTo(expected("rfc9901-A.3-expected.json").get("processed_payload"));
    }

    @Test
    @SuppressWarnings("unchecked")
    void rfc9901_5_1_allTenDisclosuresIncludingBothArrayElements() {
        Map<String, Object> claims = resolveVector("rfc9901-5.1-sd-jwt.txt");
        assertThat(claims).containsEntry("given_name", "John").containsEntry("family_name", "Doe")
                .containsEntry("email", "johndoe@example.com").containsEntry("phone_number", "+1-202-555-0101")
                .containsEntry("phone_number_verified", true).containsEntry("birthdate", "1940-01-01")
                .containsEntry("updated_at", 1570000000L).containsEntry("nationalities", List.of("US", "DE"))
                .doesNotContainKeys("_sd", "_sd_alg");
        assertThat((Map<String, Object>) claims.get("address")).containsEntry("country", "US");
    }

    @Test
    @SuppressWarnings("unchecked")
    void rfc9901_A3_issuedCredentialWithAll27DisclosuresResolves() {
        Map<String, Object> claims = resolveVector("rfc9901-A.3-sd-jwt-vc-issued.txt");
        assertThat(claims).containsEntry("vct", "urn:eudi:pid:de:1").containsEntry("nationalities", List.of("DE"))
                .doesNotContainKeys("_sd", "_sd_alg");
        assertThat((Map<String, Object>) claims.get("age_equal_or_over"))
                .containsEntry("18", true).containsEntry("65", false).doesNotContainKey("_sd");
    }

    @Test
    void sdJwtVcDraft19PresentationsResolve() {
        assertThat(resolveVector("sd-jwt-vc-19-2.3.2-presentation-kb.txt")).doesNotContainKeys("_sd", "_sd_alg");
        assertThat(resolveVector("sd-jwt-vc-19-2.3.2-presentation-no-kb.txt")).doesNotContainKeys("_sd", "_sd_alg");
    }

    @Test
    void noDisclosuresDropsDigestsAndDecoysButKeepsPlainClaims() {
        SdJwt sdJwt = SdJwt.parse(vector("rfc9901-5.2-sd-jwt-kb.txt"), 100, 64 * 1024);
        Map<String, Object> claims = SdJwtDisclosures.resolve(issuerPayload(sdJwt), List.of(), "sha-256");
        assertThat(claims).containsEntry("sub", "user_42").containsEntry("nationalities", List.of())
                .doesNotContainKeys("_sd", "_sd_alg", "family_name");
    }

    @Test
    void doesNotMutateTheInputPayload() {
        SdJwt sdJwt = SdJwt.parse(vector("rfc9901-5.2-sd-jwt-kb.txt"), 100, 64 * 1024);
        Map<String, Object> payload = issuerPayload(sdJwt);
        String before = payload.toString();
        SdJwtDisclosures.resolve(payload, sdJwt.disclosures(), "sha-256");
        assertThat(payload.toString()).isEqualTo(before);
    }

    @Test
    void sdAlgOfReadsTheTopLevelClaimAndDefaultsToSha256() {
        assertThat(SdJwtDisclosures.sdAlgOf(obj("_sd_alg", "sha-384"))).isEqualTo("sha-384");
        assertThat(SdJwtDisclosures.sdAlgOf(obj("sub", "x"))).isEqualTo("sha-256");
        assertCode(() -> SdJwtDisclosures.sdAlgOf(obj("_sd_alg", "md5")), WalletErrorCode.ALGORITHM_NOT_ALLOWED);
        assertCode(() -> SdJwtDisclosures.sdAlgOf(obj("_sd_alg", 256L)), WalletErrorCode.ALGORITHM_NOT_ALLOWED);
    }

    @Test
    void sha384DigestsResolveAndAreNotConfusedWithSha256() {
        String d = disclosure("salt-1", "given_name", "Erika");
        Map<String, Object> payload384 = obj("_sd_alg", "sha-384",
                "_sd", List.of(SdJwtDisclosures.digest(d, "sha-384")));
        assertThat(SdJwtDisclosures.resolve(payload384, List.of(d), "sha-384")).isEqualTo(obj("given_name", "Erika"));
        assertThat(SdJwtDisclosures.resolve(payload384, List.of(d), null)).isEqualTo(obj("given_name", "Erika"));

        // the same disclosure is unreferenced if the issuer's digests were SHA-256 but the payload declares sha-384
        Map<String, Object> mixed = obj("_sd_alg", "sha-384", "_sd", List.of(sha256(d)));
        assertCode(() -> SdJwtDisclosures.resolve(mixed, List.of(d), "sha-384"), WalletErrorCode.DISCLOSURE_INVALID);
    }

    @Test
    void syntheticArrayElementAndNestedObjectDisclosures() {
        String inner = disclosure("s1", "locality", "Berlin");
        String elem = disclosure("s2", obj("_sd", List.of(sha256(inner))));
        Map<String, Object> payload = obj("places", List.of("plain", obj("...", sha256(elem)), obj("...", "decoy")));
        assertThat(SdJwtDisclosures.resolve(payload, List.of(inner, elem), "sha-256"))
                .isEqualTo(obj("places", List.of("plain", obj("locality", "Berlin"))));
    }

    // ---------------------------------------------------------------- negative

    @Test
    void sameDisclosureSentTwiceIsDisclosureInvalid() {
        assertInvalid(obj("_sd", List.of(sha256(FAMILY_NAME))), List.of(FAMILY_NAME, FAMILY_NAME));
    }

    @Test
    void sameDigestTwiceInThePayloadIsDisclosureInvalid() {
        String digest = sha256(FAMILY_NAME);
        assertInvalid(obj("_sd", List.of(digest, digest)), List.of(FAMILY_NAME));
        assertInvalid(obj("_sd", List.of(digest), "nested", obj("_sd", List.of(digest))), List.of(FAMILY_NAME));
        // also for decoys / digests without a disclosure
        assertInvalid(obj("_sd", List.of("decoy"), "a", List.of(obj("...", "decoy"))), List.of());
    }

    @Test
    void digestReferencedFromWithinADisclosedValueAndThePayloadIsDisclosureInvalid() {
        // a digest that appears again inside a disclosed value would make the same claim revealed twice
        String inner = disclosure("s1", "c", "v");
        String outer = disclosure("s2", "o", obj("_sd", List.of(sha256(inner))));
        assertInvalid(obj("_sd", List.of(sha256(outer), sha256(inner))), List.of(inner, outer));
    }

    @Test
    void unreferencedDisclosureIsDisclosureInvalid() {
        SdJwt sdJwt = SdJwt.parse(vector("rfc9901-5.2-sd-jwt-kb.txt"), 100, 64 * 1024);
        List<String> withExtra = new ArrayList<>(sdJwt.disclosures());
        // RFC 9901 §5.2 reuses the §5.1 issuer JWT, so the §5.1 email disclosure is referenced (positive control) ...
        withExtra.add(EMAIL);
        Map<String, Object> payload = issuerPayload(sdJwt);
        assertThat(SdJwtDisclosures.resolve(payload, withExtra, "sha-256")).containsEntry("email", "johndoe@example.com");
        // ... while a disclosure the issuer never signed a digest for is not
        withExtra.add(disclosure("foreign", "email", "attacker@example.com"));
        assertInvalid(payload, withExtra);
    }

    @Test
    void disclosureOverwritingAPlainClaimIsDisclosureInvalid() {
        assertInvalid(obj("family_name", "Plain", "_sd", List.of(sha256(FAMILY_NAME))), List.of(FAMILY_NAME));
    }

    @Test
    void twoDisclosuresForTheSameNameAtOneLevelIsDisclosureInvalid() {
        String other = disclosure("other-salt", "family_name", "Mustermann");
        assertInvalid(obj("_sd", List.of(sha256(FAMILY_NAME), sha256(other))), List.of(FAMILY_NAME, other));
    }

    @Test
    void reservedClaimNamesAreDisclosureInvalid() {
        String sd = disclosure("s", "_sd", List.of("x"));
        String dots = disclosure("s", "...", "x");
        assertInvalid(obj("_sd", List.of(sha256(sd))), List.of(sd));
        assertInvalid(obj("_sd", List.of(sha256(dots))), List.of(dots));
    }

    @Test
    void wrongDisclosureShapeForThePositionIsDisclosureInvalid() {
        // RFC 9901 §7.1 3.c.ii.1 / 3.c.iii.1
        String objectProp = disclosure("s", "n", "v");
        String arrayElem = disclosure("s", "v");
        assertInvalid(obj("a", List.of(obj("...", sha256(objectProp)))), List.of(objectProp));
        assertInvalid(obj("_sd", List.of(sha256(arrayElem))), List.of(arrayElem));
    }

    @Test
    void malformedDisclosuresAreDisclosureInvalid() {
        List<String> bad = List.of(
                "!!!!",                                   // not base64url
                "WyJzIiwgMV0=",                           // padded
                b64("not json"),
                b64("{\"salt\":\"s\"}"),                  // not an array
                b64("[\"s\"]"),                           // one element
                b64("[\"s\",\"n\",\"v\",\"x\"]"),         // four elements
                b64("[1,\"n\",\"v\"]"),                   // salt not a string
                b64("[\"s\",2,\"v\"]"),                   // name not a string
                b64("[\"s\",\"n\",{\"a\":1,\"a\":2}]"),   // duplicate member
                b64("[\"s\",\"n\",\"v\"] trailing"),
                Base64.getUrlEncoder().withoutPadding()
                        .encodeToString(new byte[] {'[', '"', (byte) 0xC3, '"', ',', '1', ']'}), // invalid UTF-8
                "");
        for (String d : bad) {
            assertCode(() -> SdJwtDisclosures.resolve(obj("_sd", List.of(sha256(d.isEmpty() ? "x" : d))), List.of(d),
                    "sha-256"), WalletErrorCode.DISCLOSURE_INVALID);
        }
    }

    @Test
    void malformedDigestContainersAreDisclosureInvalid() {
        assertInvalid(obj("_sd", "not-an-array"), List.of());
        assertInvalid(obj("_sd", List.of(1L)), List.of());
        assertInvalid(obj("a", List.of(obj("...", 1L))), List.of());
        assertInvalid(obj("a", List.of(obj("...", "d", "extra", "x"))), List.of());
        assertInvalid(obj("a", obj("...", "d")), List.of());           // "..." outside an array element
        assertInvalid(obj("a", obj("_sd_alg", "sha-256")), List.of());  // _sd_alg only at the top level
    }

    @Test
    void algorithmNotInAllowListOrMismatchingThePayload() {
        assertCode(() -> SdJwtDisclosures.resolve(obj("_sd_alg", "md5"), List.of(), "md5"),
                WalletErrorCode.ALGORITHM_NOT_ALLOWED);
        assertCode(() -> SdJwtDisclosures.resolve(obj("_sd_alg", "md5"), List.of(), null),
                WalletErrorCode.ALGORITHM_NOT_ALLOWED);
        assertCode(() -> SdJwtDisclosures.resolve(obj("_sd_alg", "sha-384"), List.of(), "sha-256"),
                WalletErrorCode.ALGORITHM_NOT_ALLOWED);
        assertCode(() -> SdJwtDisclosures.resolve(obj("sub", "x"), List.of(), "sha-384"),
                WalletErrorCode.ALGORITHM_NOT_ALLOWED); // absent _sd_alg means sha-256
    }

    @Test
    void recursionDeeperThanTheLimitIsLimitExceeded() {
        // a chain of nested disclosures: each value is an object whose _sd points to the next one down
        List<String> chain = new ArrayList<>();
        String current = disclosure("s0", "leaf", "v");
        chain.add(current);
        for (int i = 1; i < 20; i++) {
            current = disclosure("s" + i, "c", obj("_sd", List.of(sha256(current))));
            chain.add(current);
        }
        Map<String, Object> payload = obj("_sd", List.of(sha256(current)));
        assertCode(() -> SdJwtDisclosures.resolve(payload, chain, "sha-256"), WalletErrorCode.LIMIT_EXCEEDED);
        assertThat(SdJwtDisclosures.resolve(payload, chain, "sha-256", 32)).containsKey("c");

        Object deep = "v";
        for (int i = 0; i < SdJwtDisclosures.DEFAULT_MAX_DEPTH + 1; i++) {
            deep = List.of(deep);
        }
        Map<String, Object> plainDeep = obj("a", deep);
        assertCode(() -> SdJwtDisclosures.resolve(plainDeep, List.of(), "sha-256"), WalletErrorCode.LIMIT_EXCEEDED);
    }

    @Test
    void nullArgumentsAreInvalidResponse() {
        assertCode(() -> SdJwtDisclosures.resolve(null, List.of(), "sha-256"), WalletErrorCode.INVALID_RESPONSE);
        assertCode(() -> SdJwtDisclosures.resolve(obj(), null, "sha-256"), WalletErrorCode.INVALID_RESPONSE);
    }

    @Test
    void arrayElementDisclosureFromTheRfcResolves() {
        assertThat(SdJwtDisclosures.resolve(obj("n", List.of(obj("...", sha256(NATIONALITY_US)))),
                List.of(NATIONALITY_US), "sha-256")).isEqualTo(obj("n", List.of("US")));
        assertThat(SdJwtDisclosures.resolve(obj("_sd", List.of(sha256(GIVEN_NAME))), List.of(GIVEN_NAME), "sha-256"))
                .isEqualTo(obj("given_name", "John"));
    }
}
