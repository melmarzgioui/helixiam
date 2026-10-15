/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.wallet.dcql;

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ObjectNode;
import io.helixiam.authorization.federation.wallet.PresentationVerifier;
import io.helixiam.authorization.federation.wallet.VerificationContext;
import io.helixiam.authorization.federation.wallet.VerifiedPresentation;
import io.helixiam.authorization.federation.wallet.WalletErrorCode;
import io.helixiam.authorization.federation.wallet.WalletVerificationException;
import io.helixiam.authorization.federation.wallet.sdjwt.SdJwtVcPresentationVerifier;
import io.helixiam.authorization.federation.wallet.status.StatusEvaluator;
import io.helixiam.authorization.federation.wallet.status.StatusPolicy;
import io.helixiam.authorization.federation.wallet.status.StatusReference;
import io.helixiam.authorization.federation.wallet.testwallet.TestWallet;
import io.helixiam.authorization.federation.wallet.trust.IssuerTrustValidator;
import io.helixiam.authorization.federation.wallet.trust.TrustAnchors.RevocationMode;
import io.helixiam.testsupport.LogCapture;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;

import java.io.InputStream;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * {@link DcqlResultMatcher}: the {@code vp_token} shape (OpenID4VP §8.1), credential-set satisfaction (§6.2, §6.4.2),
 * type binding of each presentation to its query, required claims, and the dropping of over-disclosed claims (§6.4,
 * §14.9). Most tests use stub verifiers so that each one isolates the matcher; the last test runs the real SD-JWT VC
 * verifier end to end.
 */
class DcqlResultMatcherTest {

    private static final ObjectMapper JSON = new ObjectMapper();
    private static final String SD_JWT = "dc+sd-jwt";
    private static final String MDOC = "mso_mdoc";
    private static final String NS = "eu.europa.ec.eudi.pid.1";
    private static final String PID_VCT = "urn:eudi:pid:1";
    private static final String CLIENT_ID = "x509_san_dns:verifier.example";
    private static final String NONCE = "n-0S6_WzA2Mj";
    private static final VerificationContext CTX = new VerificationContext(CLIENT_ID, NONCE,
            "https://verifier.example/wallet/response", null, Instant.now(), Duration.ofSeconds(60), null, null,
            Set.of(PID_VCT), NS, false);

    private static final ObjectNode PRESET = new DcqlQueryBuilder().pidQuery(new PidQuerySpec(List.of(PID_VCT),
            PidQuerySpec.DEFAULT_MDOC_DOCTYPE, List.of("given_name", "family_name", "birthdate")),
            List.of(SD_JWT, MDOC));

    /** Raw presentation string -> what the stub verifier returns for it. */
    private final Map<String, VerifiedPresentation> results = new HashMap<>();
    private final List<VerificationContext> seenContexts = new ArrayList<>();

    // ------------------------------------------------------------------------------------------- fixtures

    private PresentationVerifier stub(final String format) {
        return new PresentationVerifier() {
            @Override
            public String format() {
                return format;
            }

            @Override
            public VerifiedPresentation verify(final String raw, final VerificationContext context) {
                seenContexts.add(context);
                final VerifiedPresentation result = results.get(raw);
                if (result == null) {
                    throw new WalletVerificationException(WalletErrorCode.NONCE_MISMATCH, "stub: unknown");
                }
                return result;
            }
        };
    }

    private Map<String, PresentationVerifier> verifiers() {
        return Map.of(SD_JWT, stub(SD_JWT), MDOC, stub(MDOC));
    }

    private static VerifiedPresentation presentation(final String format, final String type,
            final Map<String, Object> claims) {
        return new VerifiedPresentation(format, type, claims, "CN=PID Issuer", "1f", "VALID");
    }

    private static Map<String, Object> sdJwtPid() {
        final Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("given_name", "Erika");
        claims.put("family_name", "Mustermann");
        claims.put("birthdate", "1964-08-12");
        return claims;
    }

    private static Map<String, Object> mdocPid(final Map<String, Object> extra) {
        final Map<String, Object> elements = new LinkedHashMap<>();
        elements.put("given_name", "Erika");
        elements.put("family_name", "Mustermann");
        elements.put("birth_date", "1964-08-12");
        elements.putAll(extra);
        return Map.of(NS, elements);
    }

    private String give(final VerifiedPresentation result) {
        final String raw = "vp-" + results.size();
        results.put(raw, result);
        return raw;
    }

    private String sdJwt() {
        return give(presentation(SD_JWT, PID_VCT, sdJwtPid()));
    }

    private String mdoc() {
        return give(presentation(MDOC, NS, mdocPid(Map.of())));
    }

    private static JsonNode json(final String text) {
        try {
            return JSON.readTree(text);
        } catch (final Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static ObjectNode query(final String text) {
        return (ObjectNode) json(text);
    }

    private MatchedPresentations match(final String vpToken) {
        return match(json(vpToken), PRESET);
    }

    private MatchedPresentations match(final JsonNode vpToken, final ObjectNode query) {
        return new DcqlResultMatcher().match(vpToken, query, verifiers(), CTX);
    }

    private static void assertRefused(final Executable call, final WalletErrorCode code) {
        assertThatThrownBy(call::execute).isInstanceOf(WalletVerificationException.class)
                .satisfies(e -> assertThat(((WalletVerificationException) e).code()).isEqualTo(code));
    }

    // ------------------------------------------------------------------------------------------- vp_token shape

    @Test
    void vpTokenAsAStringIsRefused() {
        final String raw = sdJwt();

        assertRefused(() -> match(JSON.getNodeFactory().textNode(raw), PRESET), WalletErrorCode.INVALID_RESPONSE);
    }

    @Test
    void missingVpTokenIsRefused() {
        assertRefused(() -> match(null, PRESET), WalletErrorCode.INVALID_RESPONSE);
        assertRefused(() -> match(JSON.getNodeFactory().nullNode(), PRESET), WalletErrorCode.INVALID_RESPONSE);
    }

    @Test
    void aSinglePresentationNotInAnArrayIsRefused() {
        assertRefused(() -> match("{\"pid_sd_jwt\": \"" + sdJwt() + "\"}"), WalletErrorCode.INVALID_RESPONSE);
    }

    @Test
    void anObjectEntryIsRefused() {
        assertRefused(() -> match("{\"pid_sd_jwt\": {\"0\": \"" + sdJwt() + "\"}}"), WalletErrorCode.INVALID_RESPONSE);
    }

    @Test
    void anEmptyArrayIsRefused() {
        assertRefused(() -> match("{\"pid_mdoc\": [], \"pid_sd_jwt\": [\"" + sdJwt() + "\"]}"),
                WalletErrorCode.INVALID_RESPONSE);
    }

    @Test
    void aNonStringPresentationIsRefused() {
        assertRefused(() -> match("{\"pid_sd_jwt\": [42]}"), WalletErrorCode.INVALID_RESPONSE);
        assertRefused(() -> match("{\"pid_sd_jwt\": [{\"a\": 1}]}"), WalletErrorCode.INVALID_RESPONSE);
    }

    @Test
    void anUnknownQueryIdIsRefused() {
        assertRefused(() -> match("{\"pid_sd_jwt\": [\"" + sdJwt() + "\"], \"other\": [\"" + mdoc() + "\"]}"),
                WalletErrorCode.INVALID_RESPONSE);
    }

    @Test
    void twoPresentationsForASingleQueryAreRefused() {
        assertRefused(() -> match("{\"pid_sd_jwt\": [\"" + sdJwt() + "\", \"" + sdJwt() + "\"]}"),
                WalletErrorCode.INVALID_RESPONSE);
    }

    @Test
    void multipleTrueAcceptsSeveralPresentations() {
        final ObjectNode query = query("""
                { "credentials": [ { "id": "pids", "format": "dc+sd-jwt", "multiple": true,
                    "meta": { "vct_values": ["urn:eudi:pid:1"] }, "claims": [ {"path": ["given_name"]} ] } ] }""");

        final MatchedPresentations result =
                match(json("{\"pids\": [\"" + sdJwt() + "\", \"" + sdJwt() + "\"]}"), query);

        assertThat(result.presentations()).hasSize(2);
    }

    // ------------------------------------------------------------------------------------------- credential sets

    @Test
    void onlyTheMdocQueryAnsweredIsSatisfiedThroughCredentialSets() {
        final MatchedPresentations result = match("{\"pid_mdoc\": [\"" + mdoc() + "\"]}");

        assertThat(result.presentations()).singleElement().satisfies(p -> {
            assertThat(p.format()).isEqualTo(MDOC);
            assertThat(p.credentialType()).isEqualTo(NS);
            assertThat(p.claims()).isEqualTo(mdocPid(Map.of()));
        });
        assertThat(result.droppedClaimNames()).isEmpty();
    }

    @Test
    void onlyTheSdJwtQueryAnsweredIsSatisfied() {
        final MatchedPresentations result = match("{\"pid_sd_jwt\": [\"" + sdJwt() + "\"]}");

        assertThat(result.presentations()).singleElement().satisfies(p -> {
            assertThat(p.format()).isEqualTo(SD_JWT);
            assertThat(p.claims()).isEqualTo(sdJwtPid());
            assertThat(p.issuerSubjectDn()).isEqualTo("CN=PID Issuer");
            assertThat(p.issuerSerialHex()).isEqualTo("1f");
            assertThat(p.statusResult()).isEqualTo("VALID");
        });
    }

    @Test
    void bothAnsweredAreBothKeptInQueryOrder() {
        final MatchedPresentations result =
                match("{\"pid_mdoc\": [\"" + mdoc() + "\"], \"pid_sd_jwt\": [\"" + sdJwt() + "\"]}");

        assertThat(result.presentations()).extracting(VerifiedPresentation::format).containsExactly(SD_JWT, MDOC);
    }

    @Test
    void neitherAnsweredIsNotSatisfied() {
        assertRefused(() -> match("{}"), WalletErrorCode.DCQL_NOT_SATISFIED);
    }

    @Test
    void withoutCredentialSetsEveryQueryIsRequired() {
        final ObjectNode query = query("""
                { "credentials": [
                    { "id": "a", "format": "dc+sd-jwt", "meta": { "vct_values": ["urn:eudi:pid:1"] } },
                    { "id": "b", "format": "mso_mdoc", "meta": { "doctype_value": "eu.europa.ec.eudi.pid.1" } } ] }""");

        assertRefused(() -> match(json("{\"a\": [\"" + sdJwt() + "\"]}"), query), WalletErrorCode.DCQL_NOT_SATISFIED);
        assertThat(match(json("{\"a\": [\"" + sdJwt() + "\"], \"b\": [\"" + mdoc() + "\"]}"), query).presentations())
                .hasSize(2);
    }

    /** OpenID4VP Appendix D credential_sets example (vector file), with optional "nice_to_have". */
    private static ObjectNode appendixD() throws Exception {
        try (InputStream in = DcqlResultMatcherTest.class
                .getResourceAsStream("/wallet/vectors/openid4vp/openid4vp-1.0-dcql-examples.json")) {
            return (ObjectNode) JSON.readTree(in).get("appendix_d_credential_sets");
        }
    }

    private String answer(final String vct, final String... claimPaths) {
        final Map<String, Object> claims = new LinkedHashMap<>();
        for (final String path : claimPaths) {
            final String[] parts = path.split("\\.");
            if (parts.length == 1) {
                claims.put(path, "v");
            } else {
                claims.put(parts[0], Map.of(parts[1], "v"));
            }
        }
        return give(presentation(SD_JWT, vct, claims));
    }

    private String pidAnswer() {
        return answer("https://credentials.example.com/identity_credential", "given_name", "family_name",
                "address.street_address");
    }

    private String reduced1() {
        return answer("https://credentials.example.com/reduced_identity_credential", "family_name", "given_name");
    }

    private String reduced2() {
        return answer("https://cred.example/residence_credential", "postal_code", "locality", "region");
    }

    private String niceToHave() {
        return answer("https://company.example/company_rewards", "rewards_number");
    }

    @Test
    void appendixDVectorAMultiCredentialOptionNeedsAllItsIds() throws Exception {
        final ObjectNode query = appendixD();

        assertRefused(() -> match(json("{\"pid_reduced_cred_1\": [\"" + reduced1() + "\"]}"), query),
                WalletErrorCode.DCQL_NOT_SATISFIED);
        assertThat(match(json("{\"pid_reduced_cred_1\": [\"" + reduced1() + "\"], \"pid_reduced_cred_2\": [\""
                + reduced2() + "\"]}"), query).presentations()).hasSize(2);
    }

    @Test
    void appendixDVectorAnOptionalSetAloneDoesNotSatisfyTheRequiredOne() throws Exception {
        final ObjectNode query = appendixD();

        assertRefused(() -> match(json("{\"nice_to_have\": [\"" + niceToHave() + "\"]}"), query),
                WalletErrorCode.DCQL_NOT_SATISFIED);
        assertThat(match(json("{\"pid\": [\"" + pidAnswer() + "\"], \"nice_to_have\": [\"" + niceToHave() + "\"]}"),
                query).presentations()).hasSize(2);
    }

    @Test
    void anAnswerOutsideEverySatisfiedOptionIsRefusedNotKept() throws Exception {
        final ObjectNode query = appendixD();

        // "pid" satisfies the required set; pid_reduced_cred_1 alone completes no option.
        assertRefused(() -> match(json("{\"pid\": [\"" + pidAnswer() + "\"], \"pid_reduced_cred_1\": [\""
                + reduced1() + "\"]}"), query), WalletErrorCode.INVALID_RESPONSE);
    }

    // ------------------------------------------------------------------------------------------- verification

    @Test
    void aFormatWithoutAVerifierIsRefused() {
        final Map<String, PresentationVerifier> sdJwtOnly = Map.of(SD_JWT, stub(SD_JWT));
        final String raw = mdoc();

        assertRefused(() -> new DcqlResultMatcher().match(json("{\"pid_mdoc\": [\"" + raw + "\"]}"), PRESET,
                sdJwtOnly, CTX), WalletErrorCode.INVALID_RESPONSE);
    }

    @Test
    void verifierFailuresPassThrough() {
        assertRefused(() -> match("{\"pid_sd_jwt\": [\"not-a-known-presentation\"]}"), WalletErrorCode.NONCE_MISMATCH);
    }

    @Test
    void theSameContextIsUsedForEveryPresentation() {
        match("{\"pid_mdoc\": [\"" + mdoc() + "\"], \"pid_sd_jwt\": [\"" + sdJwt() + "\"]}");

        assertThat(seenContexts).hasSize(2).allSatisfy(c -> assertThat(c).isSameAs(CTX));
    }

    @Test
    void anSdJwtWhoseTypeIsNotInItsQueryIsRefused() {
        final String raw = give(presentation(SD_JWT, "urn:eudi:pid:de:1", sdJwtPid()));

        assertRefused(() -> match("{\"pid_sd_jwt\": [\"" + raw + "\"]}"), WalletErrorCode.INVALID_RESPONSE);
    }

    @Test
    void anMdocWhoseDocTypeIsNotItsQuerysIsRefused() {
        final String raw = give(presentation(MDOC, "org.iso.18013.5.1.mDL", mdocPid(Map.of())));

        assertRefused(() -> match("{\"pid_mdoc\": [\"" + raw + "\"]}"), WalletErrorCode.INVALID_RESPONSE);
    }

    @Test
    void aPresentationOfAnotherFormatThanItsQueryIsRefused() {
        // An mdoc verifier result under the SD-JWT query (a mis-wired verifier map must not pass).
        final String raw = give(presentation(MDOC, PID_VCT, sdJwtPid()));

        assertRefused(() -> match("{\"pid_sd_jwt\": [\"" + raw + "\"]}"), WalletErrorCode.INVALID_RESPONSE);
    }

    // ------------------------------------------------------------------------------------------- claims

    @Test
    void aRequestedClaimThatIsAbsentIsNotSatisfied() {
        final Map<String, Object> claims = sdJwtPid();
        claims.remove("birthdate");
        final String raw = give(presentation(SD_JWT, PID_VCT, claims));

        assertRefused(() -> match("{\"pid_sd_jwt\": [\"" + raw + "\"]}"), WalletErrorCode.DCQL_NOT_SATISFIED);
    }

    @Test
    void anMdocWithoutNameSpacesIsNotSatisfiedWhenClaimsAreRequested() {
        // Task 12: an mdoc without issuerSigned.nameSpaces verifies with empty claims.
        final String raw = give(presentation(MDOC, NS, Map.of()));

        assertRefused(() -> match("{\"pid_mdoc\": [\"" + raw + "\"]}"), WalletErrorCode.DCQL_NOT_SATISFIED);
    }

    @Test
    void aNestedRequestedPathUnderANonObjectIsNotSatisfied() {
        final ObjectNode query = query("""
                { "credentials": [ { "id": "a", "format": "dc+sd-jwt", "meta": { "vct_values": ["urn:eudi:pid:1"] },
                    "claims": [ {"path": ["address", "street_address"]} ] } ] }""");
        final String raw = give(presentation(SD_JWT, PID_VCT, Map.of("address", "Heidestraße 17")));

        assertRefused(() -> match(json("{\"a\": [\"" + raw + "\"]}"), query), WalletErrorCode.DCQL_NOT_SATISFIED);
    }

    @Test
    void overDisclosedClaims_areDroppedAndOnlyNamesLogged() {
        final String address = "Heidestraße 17, 51147 Köln";
        final String raw = give(presentation(MDOC, NS, mdocPid(Map.of("resident_address", address))));

        final MatchedPresentations result;
        try (LogCapture log = LogCapture.of(DcqlResultMatcher.class)) {
            result = match("{\"pid_mdoc\": [\"" + raw + "\"]}");

            assertThat(log.text()).contains("resident_address").doesNotContain(address).doesNotContain("Heidestraße")
                    .doesNotContain("Erika").doesNotContain(raw);
        }
        assertThat(result.presentations()).singleElement()
                .satisfies(p -> assertThat(p.claims()).isEqualTo(mdocPid(Map.of())));
        assertThat(result.droppedClaimNames()).containsExactly(NS + "/resident_address");
    }

    @Test
    void overDisclosedNestedMembersAreDroppedAndRequestedOnesKept() {
        final ObjectNode query = query("""
                { "credentials": [ { "id": "a", "format": "dc+sd-jwt", "meta": { "vct_values": ["urn:eudi:pid:1"] },
                    "claims": [ {"path": ["given_name"]}, {"path": ["address", "street_address"]} ] } ] }""");
        final Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("given_name", "Erika");
        claims.put("sub", "subject-1");
        claims.put("address", Map.of("street_address", "Heidestraße 17", "locality", "Köln"));
        final String raw = give(presentation(SD_JWT, PID_VCT, claims));

        final MatchedPresentations result = match(json("{\"a\": [\"" + raw + "\"]}"), query);

        assertThat(result.presentations().get(0).claims()).isEqualTo(Map.of("given_name", "Erika",
                "address", Map.of("street_address", "Heidestraße 17")));
        assertThat(result.droppedClaimNames()).containsExactlyInAnyOrder("sub", "address/locality");
    }

    @Test
    void aWholeObjectRequestKeepsAllItsMembers() {
        final ObjectNode query = query("""
                { "credentials": [ { "id": "a", "format": "dc+sd-jwt", "meta": { "vct_values": ["urn:eudi:pid:1"] },
                    "claims": [ {"path": ["place_of_birth"]} ] } ] }""");
        final Map<String, Object> pob = Map.of("locality", "Berlin", "country", "DE");
        final String raw = give(presentation(SD_JWT, PID_VCT, Map.of("place_of_birth", pob)));

        assertThat(match(json("{\"a\": [\"" + raw + "\"]}"), query).presentations().get(0).claims())
                .isEqualTo(Map.of("place_of_birth", pob));
    }

    @Test
    void droppedNamesAreSanitisedAndBounded() {
        final String longName = "x".repeat(500);
        final Map<String, Object> claims = sdJwtPid();
        claims.put("evil\nname", "v");
        claims.put(longName, "v");
        final String raw = give(presentation(SD_JWT, PID_VCT, claims));

        final MatchedPresentations result;
        try (LogCapture log = LogCapture.of(DcqlResultMatcher.class)) {
            result = match("{\"pid_sd_jwt\": [\"" + raw + "\"]}");
            assertThat(log.text()).doesNotContain("evil\nname").doesNotContain(longName);
        }
        assertThat(result.droppedClaimNames()).containsExactlyInAnyOrder("evil_name", "x".repeat(61) + "...")
                .allSatisfy(n -> assertThat(n.length()).isLessThanOrEqualTo(DcqlResultMatcher.MAX_LOGGED_NAME_LENGTH));
    }

    @Test
    void droppedNamesAreCappedWithACountOfTheRest() {
        final Map<String, Object> claims = sdJwtPid();
        for (int i = 0; i < 40; i++) {
            claims.put("extra_%02d".formatted(i), "v");
        }
        final String raw = give(presentation(SD_JWT, PID_VCT, claims));

        final MatchedPresentations result;
        try (LogCapture log = LogCapture.of(DcqlResultMatcher.class)) {
            result = match("{\"pid_sd_jwt\": [\"" + raw + "\"]}");
            assertThat(log.text()).contains("extra_31").doesNotContain("extra_32").contains("(+8 more)");
        }
        assertThat(result.droppedClaimNames()).hasSize(DcqlResultMatcher.MAX_DROPPED_NAMES + 1)
                .contains("extra_00", "extra_31", "(+8 more)").doesNotContain("extra_32", "extra_39");
    }

    @Test
    void aNullCredentialTypeIsRefused() {
        final String raw = give(presentation(SD_JWT, null, sdJwtPid()));

        assertRefused(() -> match("{\"pid_sd_jwt\": [\"" + raw + "\"]}"), WalletErrorCode.INVALID_RESPONSE);
    }

    @Test
    void aRequestedSdJwtClaimWhoseValueIsNullIsNotSatisfied() {
        final Map<String, Object> claims = sdJwtPid();
        claims.put("birthdate", null);
        final String raw = give(presentation(SD_JWT, PID_VCT, claims));

        assertRefused(() -> match("{\"pid_sd_jwt\": [\"" + raw + "\"]}"), WalletErrorCode.DCQL_NOT_SATISFIED);
    }

    @Test
    void aRequestedMdocElementWhoseValueIsNullIsNotSatisfied() {
        final Map<String, Object> nullBirthDate = new HashMap<>();
        nullBirthDate.put("birth_date", null);
        final String raw = give(presentation(MDOC, NS, mdocPid(nullBirthDate)));

        assertRefused(() -> match("{\"pid_mdoc\": [\"" + raw + "\"]}"), WalletErrorCode.DCQL_NOT_SATISFIED);
    }

    // ------------------------------------------------------------------------------------------- claim_sets (Task 21a)

    private static Map<String, Object> withSubjectClaims(final Map<String, Object> claims, final boolean number,
            final boolean country) {
        final Map<String, Object> out = new LinkedHashMap<>(claims);
        if (number) {
            out.put("personal_administrative_number", "123456789");
        }
        if (country) {
            out.put("issuing_country", "NL");
        }
        return out;
    }

    @Test
    void claimSets_theFirstOption_requestedPlusBothSubjectClaims_isSatisfiedAndBothAreKept() {
        final String raw = give(presentation(SD_JWT, PID_VCT, withSubjectClaims(sdJwtPid(), true, true)));

        final MatchedPresentations result = match("{\"pid_sd_jwt\": [\"" + raw + "\"]}");

        assertThat(result.presentations().get(0).claims()).isEqualTo(withSubjectClaims(sdJwtPid(), true, true));
        assertThat(result.droppedClaimNames()).isEmpty();
    }

    @Test
    void claimSets_theLastOption_requestedOnly_isSatisfied() {
        final String raw = give(presentation(SD_JWT, PID_VCT, sdJwtPid()));

        assertThat(match("{\"pid_sd_jwt\": [\"" + raw + "\"]}").presentations().get(0).claims())
                .isEqualTo(sdJwtPid());
    }

    @Test
    void claimSets_requestedPlusCountryOnly_isSatisfied() {
        final String raw = give(presentation(SD_JWT, PID_VCT, withSubjectClaims(sdJwtPid(), false, true)));

        assertThat(match("{\"pid_sd_jwt\": [\"" + raw + "\"]}").presentations().get(0).claims())
                .containsEntry("issuing_country", "NL");
    }

    @Test
    void claimSets_bothOptionalClaimsCountAsRequested_soTheNumberAloneIsKeptNotDropped() {
        final String raw = give(presentation(SD_JWT, PID_VCT, withSubjectClaims(sdJwtPid(), true, false)));

        final MatchedPresentations result = match("{\"pid_sd_jwt\": [\"" + raw + "\"]}");

        assertThat(result.presentations().get(0).claims()).containsEntry("personal_administrative_number", "123456789");
        assertThat(result.droppedClaimNames()).isEmpty();
    }

    @Test
    void claimSets_aMissingRequestedClaimIsNotSatisfiedEvenWithBothSubjectClaims() {
        final Map<String, Object> claims = withSubjectClaims(sdJwtPid(), true, true);
        claims.remove("given_name");
        final String raw = give(presentation(SD_JWT, PID_VCT, claims));

        assertRefused(() -> match("{\"pid_sd_jwt\": [\"" + raw + "\"]}"), WalletErrorCode.DCQL_NOT_SATISFIED);
    }

    @Test
    void claimSets_aNullRequestedClaimIsStillNotSatisfied() {
        final Map<String, Object> claims = withSubjectClaims(sdJwtPid(), true, true);
        claims.put("family_name", null);
        final String raw = give(presentation(SD_JWT, PID_VCT, claims));

        assertRefused(() -> match("{\"pid_sd_jwt\": [\"" + raw + "\"]}"), WalletErrorCode.DCQL_NOT_SATISFIED);
    }

    @Test
    void claimSets_mdocWithBothSubjectElements_keepsThem() {
        final String raw = give(presentation(MDOC, NS, mdocPid(Map.of("personal_administrative_number", "123456789",
                "issuing_country", "NL", "resident_city", "Arnhem"))));

        final MatchedPresentations result = match("{\"pid_mdoc\": [\"" + raw + "\"]}");

        assertThat(result.presentations().get(0).claims()).isEqualTo(mdocPid(Map.of(
                "personal_administrative_number", "123456789", "issuing_country", "NL")));
        assertThat(result.droppedClaimNames()).containsExactly(NS + "/resident_city");
    }

    @Test
    void claimSets_anOptionIsSatisfiedOnlyWhenAllItsClaimsArePresent() {
        final ObjectNode query = query("""
                { "credentials": [ { "id": "a", "format": "dc+sd-jwt", "meta": { "vct_values": ["urn:eudi:pid:1"] },
                    "claims": [ {"id": "g", "path": ["given_name"]}, {"id": "f", "path": ["family_name"]},
                                {"id": "b", "path": ["birthdate"]} ],
                    "claim_sets": [ ["g", "f"], ["b"] ] } ] }""");
        final String onlyGiven = give(presentation(SD_JWT, PID_VCT, Map.of("given_name", "Erika")));
        final String givenAndFamily = give(presentation(SD_JWT, PID_VCT,
                Map.of("given_name", "Erika", "family_name", "Mustermann")));
        final String onlyBirthdate = give(presentation(SD_JWT, PID_VCT, Map.of("birthdate", "1964-08-12")));

        assertRefused(() -> match(json("{\"a\": [\"" + onlyGiven + "\"]}"), query), WalletErrorCode.DCQL_NOT_SATISFIED);
        assertThat(match(json("{\"a\": [\"" + givenAndFamily + "\"]}"), query).presentations()).hasSize(1);
        assertThat(match(json("{\"a\": [\"" + onlyBirthdate + "\"]}"), query).presentations()).hasSize(1);
    }

    // ------------------------------------------------------------------------------------------- our own queries

    /**
     * HAIP §5: the query carries an aki Trusted Authorities Query. It only helps the wallet pick a credential: the
     * matcher does not enforce it (the presentation verifiers' PKIX validation to the trust anchors does).
     */
    @Test
    void aBuilderQueryWithTrustedAuthorities_isMatchedLikeOneWithout() {
        final ObjectNode withAki = new DcqlQueryBuilder().pidQuery(new PidQuerySpec(List.of(PID_VCT),
                PidQuerySpec.DEFAULT_MDOC_DOCTYPE, List.of("given_name", "family_name", "birthdate")),
                List.of(SD_JWT, MDOC), List.of("s9tIpPmhxdiuNkHMEWNpYim8S8Y"));

        final MatchedPresentations result = match(json("{\"pid_sd_jwt\": [\"" + sdJwt() + "\"]}"), withAki);

        assertThat(result.presentations()).extracting(VerifiedPresentation::format).containsExactly(SD_JWT);
    }

    @Test
    void queryFeaturesTheBuilderNeverEmitsAreRefusedAsProgrammingErrors() {
        final String base = """
                { "credentials": [ { "id": "a", "format": "dc+sd-jwt", "meta": { "vct_values": ["urn:eudi:pid:1"] },
                    %s } ] }""";
        final String raw = sdJwt();
        for (final String unsupported : List.of(
                // claim_sets is supported (Task 21a) but must be well-formed: ids known, present on every claim,
                // unique, non-empty options
                "\"claims\": [ {\"id\": \"x\", \"path\": [\"given_name\"]} ], \"claim_sets\": [[\"y\"]]",
                "\"claims\": [ {\"path\": [\"given_name\"]} ], \"claim_sets\": [[\"x\"]]",
                "\"claims\": [ {\"id\": \"x\", \"path\": [\"given_name\"]}, {\"path\": [\"birthdate\"]} ], "
                        + "\"claim_sets\": [[\"x\"]]",
                "\"claims\": [ {\"id\": \"x\", \"path\": [\"given_name\"]}, {\"id\": \"x\", \"path\": [\"birthdate\"]} ], "
                        + "\"claim_sets\": [[\"x\"]]",
                "\"claims\": [ {\"id\": \"x\", \"path\": [\"given_name\"]} ], \"claim_sets\": []",
                "\"claims\": [ {\"id\": \"x\", \"path\": [\"given_name\"]} ], \"claim_sets\": [[]]",
                "\"claims\": [ {\"id\": \"x\", \"path\": [\"given_name\"]} ], \"claim_sets\": [\"x\"]",
                "\"claims\": [ {\"id\": \"x y\", \"path\": [\"given_name\"]} ], \"claim_sets\": [[\"x y\"]]",
                "\"claim_sets\": [[\"x\"]]",
                "\"claims\": [ {\"path\": [\"given_name\"], \"values\": [\"Erika\"]} ]",
                "\"claims\": [ {\"path\": [\"nationalities\", null]} ]",
                "\"claims\": [ {\"path\": [\"nationalities\", 0]} ]",
                "\"claims\": [ {\"path\": []} ]",
                "\"claims\": [ {\"path\": [\"a\",\"b\",\"c\",\"d\",\"e\",\"f\",\"g\",\"h\",\"i\"]} ]",
                // trusted_authorities is emitted (HAIP §5), but only as one well-formed aki query
                "\"trusted_authorities\": [ {\"type\": \"etsi_tl\", \"values\": [\"https://tl.example\"]} ]",
                "\"trusted_authorities\": [ {\"type\": \"aki\", \"values\": []} ]",
                "\"trusted_authorities\": [ {\"type\": \"aki\", \"values\": [\"\"]} ]",
                "\"trusted_authorities\": [ {\"type\": \"aki\"} ]",
                "\"trusted_authorities\": []")) {
            final ObjectNode query = query(base.formatted(unsupported));
            assertThatThrownBy(() -> match(json("{\"a\": [\"" + raw + "\"]}"), query))
                    .as(unsupported).isInstanceOf(IllegalArgumentException.class);
        }
    }

    @Test
    void anMdocPathMustBeNamespaceAndElement() {
        final ObjectNode query = query("""
                { "credentials": [ { "id": "m", "format": "mso_mdoc", "meta": { "doctype_value": "eu.europa.ec.eudi.pid.1" },
                    "claims": [ {"path": ["given_name"]} ] } ] }""");
        final String raw = mdoc();

        assertThatThrownBy(() -> match(json("{\"m\": [\"" + raw + "\"]}"), query))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void aCredentialSetNamingAnUnknownQueryIsAProgrammingError() {
        final ObjectNode query = query("""
                { "credentials": [ { "id": "a", "format": "dc+sd-jwt", "meta": { "vct_values": ["urn:eudi:pid:1"] } } ],
                  "credential_sets": [ { "options": [ ["a"], ["b"] ] } ] }""");
        final String raw = sdJwt();

        assertThatThrownBy(() -> match(json("{\"a\": [\"" + raw + "\"]}"), query))
                .isInstanceOf(IllegalArgumentException.class);
    }

    // ------------------------------------------------------------------------------------------- end to end

    @Test
    void realSdJwtPresentationIsMatchedAndOverDisclosureDropped() {
        final TestWallet wallet = TestWallet.create();
        final Map<String, Object> pid = new LinkedHashMap<>(sdJwtPid());
        pid.put("nationalities", List.of("DE"));
        // Task 21a: personal_administrative_number is requested now (optionally), so another unrequested claim
        // stands in for the over-disclosure.
        pid.put("document_number", "DOC-0001");
        final Instant now = Instant.now();
        final TestWallet.SdJwtCredential cred = wallet.sdJwtPid(pid, now.minusSeconds(3600),
                now.plus(Duration.ofDays(30)), Optional.empty());
        final String vp = wallet.present(cred, pid.keySet(), CLIENT_ID, NONCE);
        final VerificationContext ctx = new VerificationContext(CLIENT_ID, NONCE,
                "https://verifier.example/wallet/response", null, now, Duration.ofSeconds(60),
                wallet.pki().trustAnchors(RevocationMode.OFF),
                new StatusPolicy(false, StatusPolicy.OnUnavailable.FAIL_CLOSED, Duration.ofSeconds(900), List.of()),
                Set.of(PID_VCT), NS, false);
        final StatusEvaluator neverCalled = (ref, anchors, issuer) -> {
            throw new AssertionError("no status reference");
        };

        final MatchedPresentations result;
        try (LogCapture log = LogCapture.of(DcqlResultMatcher.class)) {
            result = new DcqlResultMatcher().match(json("{\"pid_sd_jwt\": [\"" + vp + "\"]}"), PRESET,
                    Map.of(SD_JWT, new SdJwtVcPresentationVerifier(new IssuerTrustValidator(), neverCalled)), ctx);
            assertThat(log.text()).contains("document_number").doesNotContain("DOC-0001");
        }

        assertThat(result.presentations()).singleElement().satisfies(p -> {
            assertThat(p.credentialType()).isEqualTo(PID_VCT);
            assertThat(p.claims()).isEqualTo(sdJwtPid());
        });
        assertThat(result.droppedClaimNames())
                .containsExactlyInAnyOrder("nationalities", "document_number");
    }

    @Test
    void technicalClaimsAreNeverReportedAsDropped() {
        final TestWallet wallet = TestWallet.create().withPayloadClaim("iss", TestWallet.ISSUER)
                .withPayloadClaim("nbf", Instant.now().minusSeconds(60).getEpochSecond())
                .withPayloadClaim("aka_vcts", List.of("urn:other:1"));
        final Map<String, Object> pid = new LinkedHashMap<>(sdJwtPid());
        pid.put("nationalities", List.of("DE"));
        final Instant now = Instant.now();
        final TestWallet.SdJwtCredential cred = wallet.sdJwtPid(pid, now.minusSeconds(3600),
                now.plus(Duration.ofDays(30)), Optional.of(new StatusReference(7, "https://status.example/lists/1")));
        final String vp = wallet.present(cred, pid.keySet(), CLIENT_ID, NONCE);
        final VerificationContext ctx = new VerificationContext(CLIENT_ID, NONCE,
                "https://verifier.example/wallet/response", null, now, Duration.ofSeconds(60),
                wallet.pki().trustAnchors(RevocationMode.OFF),
                new StatusPolicy(true, StatusPolicy.OnUnavailable.FAIL_CLOSED, Duration.ofSeconds(900), List.of()),
                Set.of(PID_VCT), NS, false);
        final StatusEvaluator valid = (ref, anchors, issuer) -> StatusEvaluator.VALID;

        final MatchedPresentations result = new DcqlResultMatcher().match(
                json("{\"pid_sd_jwt\": [\"" + vp + "\"]}"), PRESET,
                Map.of(SD_JWT, new SdJwtVcPresentationVerifier(new IssuerTrustValidator(), valid)), ctx);

        assertThat(result.droppedClaimNames()).containsExactly("nationalities");
        assertThat(result.presentations().get(0).statusResult()).isEqualTo("VALID");
    }
}
