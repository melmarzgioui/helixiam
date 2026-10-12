/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.wallet;

import io.helixiam.authorization.federation.wallet.dcql.MatchedPresentations;
import io.helixiam.testsupport.LogCapture;
import org.junit.jupiter.api.Test;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/**
 * Task 21a: {@link WalletSubjectResolver} — maintainer decision 1 ("administrative number, else link"). The subject is
 * an HMAC-SHA256 under the realm's pepper of either {@code issuing_country + ":" + personal_administrative_number} or
 * the normalised attribute tuple; the tuple is only ever a link key (never JIT, see {@code WalletLinkServiceTest}).
 * Fix round 1: the tuple's field set is fixed by configuration (ruling 5), number and country come from one
 * presentation (ruling 8), and an administrative-number subject also carries the tuple when the weak subject is
 * acknowledged (ruling 1, the upgrade path).
 */
class WalletSubjectResolverTest {

    private static final String SD_JWT = "dc+sd-jwt";
    private static final String MDOC = "mso_mdoc";
    private static final String NS = "eu.europa.ec.eudi.pid.1";
    private static final String REALM = "acme";
    private static final byte[] PEPPER = filled((byte) 7);
    private static final byte[] OTHER_PEPPER = filled((byte) 9);
    private static final List<String> DEFAULT_CLAIMS = List.of("given_name", "family_name", "birthdate");
    private static final List<String> WITH_PLACE_OF_BIRTH =
            List.of("given_name", "family_name", "birthdate", "place_of_birth");

    private static final WalletProviderConfig.Subject NUMBER_ONLY =
            new WalletProviderConfig.Subject(WalletProviderConfig.Subject.Strategy.ADMINISTRATIVE_NUMBER, false);
    private static final WalletProviderConfig.Subject NUMBER_ELSE_LINK =
            new WalletProviderConfig.Subject(WalletProviderConfig.Subject.Strategy.ADMINISTRATIVE_NUMBER, true);
    private static final WalletProviderConfig.Subject TUPLE_ACKNOWLEDGED =
            new WalletProviderConfig.Subject(WalletProviderConfig.Subject.Strategy.ATTRIBUTE_TUPLE, true);
    private static final WalletProviderConfig.Subject TUPLE_NOT_ACKNOWLEDGED =
            new WalletProviderConfig.Subject(WalletProviderConfig.Subject.Strategy.ATTRIBUTE_TUPLE, false);

    private static byte[] filled(final byte b) {
        final byte[] out = new byte[32];
        Arrays.fill(out, b);
        return out;
    }

    private static WalletSubjectResolver resolver(final byte[] pepper) {
        final RealmWalletPepper peppers = mock(RealmWalletPepper.class);
        when(peppers.pepper(anyString())).thenReturn(pepper);
        return new WalletSubjectResolver(peppers);
    }

    private static WalletSubject resolve(final byte[] pepper, final MatchedPresentations matched,
            final WalletProviderConfig.Subject subject) {
        return resolver(pepper).resolve(REALM, matched, subject, DEFAULT_CLAIMS);
    }

    /** A PID with names, birthdate and issuing_country NL. */
    private static Map<String, Object> pid(final String given, final String family) {
        final Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("given_name", given);
        claims.put("family_name", family);
        claims.put("birthdate", "1964-08-12");
        claims.put("issuing_country", "NL");
        return claims;
    }

    /** {@code country == null} removes issuing_country; {@code number == null} adds none. */
    private static Map<String, Object> withNumber(final Map<String, Object> claims, final String country,
            final String number) {
        final Map<String, Object> out = new LinkedHashMap<>(claims);
        out.remove("issuing_country");
        if (country != null) {
            out.put("issuing_country", country);
        }
        if (number != null) {
            out.put("personal_administrative_number", number);
        }
        return out;
    }

    private static MatchedPresentations sdJwt(final Map<String, Object> claims) {
        return new MatchedPresentations(List.of(sdJwtPresentation(claims)), Set.of());
    }

    private static VerifiedPresentation sdJwtPresentation(final Map<String, Object> claims) {
        return new VerifiedPresentation(SD_JWT, "urn:eudi:pid:1", claims, "CN=PID Issuer", "1f", "VALID");
    }

    private static VerifiedPresentation mdocPresentation(final Map<String, Object> elements) {
        return new VerifiedPresentation(MDOC, NS, Map.of(NS, elements), "CN=PID Issuer", "2f", "VALID");
    }

    private static Map<String, Object> mdocElements(final String country, final String number) {
        final Map<String, Object> elements = new LinkedHashMap<>();
        elements.put("given_name", "Erika");
        elements.put("family_name", "Mustermann");
        elements.put("birth_date", "1964-08-12");
        if (country != null) {
            elements.put("issuing_country", country);
        }
        if (number != null) {
            elements.put("personal_administrative_number", number);
        }
        return elements;
    }

    private static String hmacHex(final byte[] key, final String input) throws Exception {
        final Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(key, "HmacSHA256"));
        return HexFormat.of().formatHex(mac.doFinal(input.getBytes(StandardCharsets.UTF_8)));
    }

    private static String subjectOf(final WalletSubject subject) {
        return switch (subject) {
            case WalletSubject.AdminNumber a -> a.value();
            case WalletSubject.Tuple t -> t.value();
            case WalletSubject.Unavailable u -> throw new AssertionError("unavailable: " + u.reason());
        };
    }

    // ------------------------------------------------------------------------------------------- known answers

    @Test
    void knownAnswer_adminNumber() {
        assertThat(subjectOf(resolve(PEPPER, sdJwt(withNumber(pid("Erika", "Mustermann"), "NL", "123456789")),
                NUMBER_ONLY))).isEqualTo("236876bd2f15fa7fc6e50011b50ce1f2622b14168b79dad156764479463facd1");
    }

    @Test
    void knownAnswer_tupleEncoding() {
        // HMAC(0x07 x 32, "helix-wallet-tuple-v1;issuing_country=2:nl;family_name=10:mustermann;given_name=5:erika;"
        //                 + "birthdate=10:1964-08-12;"), computed outside Java
        assertThat(subjectOf(resolve(PEPPER, sdJwt(pid("Erika", "Mustermann")), NUMBER_ELSE_LINK)))
                .isEqualTo("37865f77f55f7a42e0683fb9e1d472723474bcaae38e10cc0d9a235099b15efb");
    }

    @Test
    void knownAnswer_tupleEncodingWithPlaceOfBirth() {
        final Map<String, Object> claims = pid("Erika", "Mustermann");
        claims.put("place_of_birth", Map.of("country", "DE", "region", "Berlin", "locality", "Berlin"));

        // ... + "place_of_birth.country=2:de;place_of_birth.region=6:berlin;place_of_birth.locality=6:berlin;"
        assertThat(subjectOf(resolver(PEPPER).resolve(REALM, sdJwt(claims), NUMBER_ELSE_LINK, WITH_PLACE_OF_BIRTH)))
                .isEqualTo("499efa11845da28bd7e5faa7055f6956aaf99bbe00798e57f7b6f42b453d91d1");
    }

    // ------------------------------------------------------------------------------------------- administrative number

    @Test
    void numberPresent_givesAdminNumber_hmacOfCountryColonNumber() throws Exception {
        final WalletSubject subject = resolve(PEPPER,
                sdJwt(withNumber(pid("Erika", "Mustermann"), "NL", "123456789")), NUMBER_ONLY);

        assertThat(subject).isInstanceOf(WalletSubject.AdminNumber.class);
        assertThat(subjectOf(subject)).isEqualTo(hmacHex(PEPPER, "NL:123456789")).matches("[0-9a-f]{64}");
    }

    @Test
    void sameNumberDifferentCountry_givesDifferentSubjects() {
        final String nl = subjectOf(resolve(PEPPER, sdJwt(withNumber(pid("Erika", "M"), "NL", "123")), NUMBER_ONLY));
        final String de = subjectOf(resolve(PEPPER, sdJwt(withNumber(pid("Erika", "M"), "DE", "123")), NUMBER_ONLY));

        assertThat(nl).isNotEqualTo(de);
    }

    @Test
    void differentPepper_givesDifferentSubject() {
        final MatchedPresentations withNumber = sdJwt(withNumber(pid("Erika", "M"), "NL", "123"));
        final MatchedPresentations without = sdJwt(pid("Erika", "M"));

        assertThat(subjectOf(resolve(PEPPER, withNumber, NUMBER_ONLY)))
                .isNotEqualTo(subjectOf(resolve(OTHER_PEPPER, withNumber, NUMBER_ONLY)));
        assertThat(subjectOf(resolve(PEPPER, without, NUMBER_ELSE_LINK)))
                .isNotEqualTo(subjectOf(resolve(OTHER_PEPPER, without, NUMBER_ELSE_LINK)));
    }

    @Test
    void theNumberIsTheSubject_whateverTheNamesSay() {
        assertThat(subjectOf(resolve(PEPPER, sdJwt(withNumber(pid("Erika", "Mustermann"), "NL", "123")),
                NUMBER_ONLY))).isEqualTo(subjectOf(resolve(PEPPER,
                sdJwt(withNumber(pid("Erika", "Gabler"), "NL", "123")), NUMBER_ONLY)));
    }

    @Test
    void numberPresent_winsUnderTheTupleStrategyToo() {
        assertThat(resolve(PEPPER, sdJwt(withNumber(pid("Erika", "M"), "NL", "123")), TUPLE_ACKNOWLEDGED))
                .isInstanceOf(WalletSubject.AdminNumber.class);
    }

    @Test
    void countryCaseAndSurroundingSpaceDoNotChangeTheAdminSubject() {
        assertThat(subjectOf(resolve(PEPPER, sdJwt(withNumber(pid("E", "M"), " nl ", " 123 ")), NUMBER_ONLY)))
                .isEqualTo(subjectOf(resolve(PEPPER, sdJwt(withNumber(pid("E", "M"), "NL", "123")), NUMBER_ONLY)));
    }

    @Test
    void numberFromAnMdocPresentationIsUsed() throws Exception {
        final WalletSubject subject = resolve(PEPPER,
                new MatchedPresentations(List.of(mdocPresentation(mdocElements("NL", "123456789"))), Set.of()),
                NUMBER_ONLY);

        assertThat(subjectOf(subject)).isEqualTo(hmacHex(PEPPER, "NL:123456789"));
    }

    @Test
    void numberAndCountryComeFromTheSamePresentation_anSdJwtWithoutCountryDoesNotHideTheMdocPair()
            throws Exception {
        // ruling 8: the SD-JWT (authoritative for attributes) lacks issuing_country; the mdoc carries both.
        final MatchedPresentations mixed = new MatchedPresentations(List.of(
                sdJwtPresentation(withNumber(pid("Erika", "Mustermann"), null, null)),
                mdocPresentation(mdocElements("NL", "123456789"))), Set.of());

        assertThat(subjectOf(resolve(PEPPER, mixed, NUMBER_ONLY))).isEqualTo(hmacHex(PEPPER, "NL:123456789"));
    }

    @Test
    void aNumberWithoutItsCountryIsNotPairedWithAnotherPresentationsCountry() {
        // SD-JWT has the number but no country; mdoc has a country but no number: no complete pair.
        final MatchedPresentations split = new MatchedPresentations(List.of(
                sdJwtPresentation(withNumber(pid("Erika", "Mustermann"), null, "123456789")),
                mdocPresentation(mdocElements("NL", null))), Set.of());

        assertThat(resolve(PEPPER, split, NUMBER_ONLY))
                .isEqualTo(new WalletSubject.Unavailable(WalletSubject.Reason.WEAK_SUBJECT_NOT_ACKNOWLEDGED));
    }

    @Test
    void bothFormatsDisagreeingOnTheNumber_isRefused() {
        final MatchedPresentations both = new MatchedPresentations(List.of(
                sdJwtPresentation(withNumber(pid("Erika", "Mustermann"), "NL", "123")),
                mdocPresentation(mdocElements("NL", "999"))), Set.of());

        assertThatThrownBy(() -> resolve(PEPPER, both, NUMBER_ONLY))
                .isInstanceOf(WalletVerificationException.class)
                .satisfies(e -> assertThat(((WalletVerificationException) e).code())
                        .isEqualTo(WalletErrorCode.INVALID_RESPONSE))
                .hasMessageNotContaining("123").hasMessageNotContaining("999");
    }

    @Test
    void bothFormatsDisagreeingOnTheCountry_isRefused() {
        final MatchedPresentations both = new MatchedPresentations(List.of(
                sdJwtPresentation(withNumber(pid("Erika", "Mustermann"), "NL", "123")),
                mdocPresentation(mdocElements("DE", "123"))), Set.of());

        assertThatThrownBy(() -> resolve(PEPPER, both, NUMBER_ONLY))
                .isInstanceOf(WalletVerificationException.class)
                .satisfies(e -> assertThat(((WalletVerificationException) e).code())
                        .isEqualTo(WalletErrorCode.INVALID_RESPONSE));
    }

    @Test
    void aNumberWithoutACountryIsNotUsed() {
        assertThat(resolve(PEPPER, sdJwt(withNumber(pid("E", "M"), null, "123")), NUMBER_ONLY))
                .isEqualTo(new WalletSubject.Unavailable(WalletSubject.Reason.WEAK_SUBJECT_NOT_ACKNOWLEDGED));
        // ... and the tuple needs the country too
        assertThat(resolve(PEPPER, sdJwt(withNumber(pid("E", "M"), null, "123")), NUMBER_ELSE_LINK))
                .isEqualTo(new WalletSubject.Unavailable(WalletSubject.Reason.MISSING_IDENTITY_ATTRIBUTES));
    }

    @Test
    void aBlankNumberCountsAsAbsent() {
        assertThat(resolve(PEPPER, sdJwt(withNumber(pid("E", "M"), "NL", "  ")), NUMBER_ELSE_LINK))
                .isInstanceOf(WalletSubject.Tuple.class);
    }

    // ------------------------------------------------------------------------------------------- upgrade path

    @Test
    void numberWithTheWeakSubjectAcknowledged_alsoCarriesTheTuple_forTheUpgradePath() {
        final String tuple = subjectOf(resolve(PEPPER, sdJwt(pid("Erika", "Mustermann")), NUMBER_ELSE_LINK));

        final WalletSubject subject = resolve(PEPPER, sdJwt(withNumber(pid("Erika", "Mustermann"), "NL", "123")),
                NUMBER_ELSE_LINK);

        assertThat(subject).isInstanceOf(WalletSubject.AdminNumber.class);
        assertThat(((WalletSubject.AdminNumber) subject).tupleValue()).isEqualTo(tuple);
    }

    @Test
    void numberWithTheFlagOff_neverComputesTheTuple() {
        final WalletSubject subject = resolve(PEPPER, sdJwt(withNumber(pid("Erika", "Mustermann"), "NL", "123")),
                NUMBER_ONLY);

        assertThat(((WalletSubject.AdminNumber) subject).tupleValue()).isNull();
    }

    @Test
    void numberWithIncompleteTupleFields_hasNoTupleButStillTheNumber() {
        final Map<String, Object> claims = withNumber(pid("Erika", "Mustermann"), "NL", "123");
        claims.remove("given_name");

        final WalletSubject subject = resolve(PEPPER, sdJwt(claims), NUMBER_ELSE_LINK);

        assertThat(subject).isInstanceOf(WalletSubject.AdminNumber.class);
        assertThat(((WalletSubject.AdminNumber) subject).tupleValue()).isNull();
    }

    // ------------------------------------------------------------------------------------------- no number

    @Test
    void numberAbsent_flagOff_isRefusedWithAReason_andThePepperIsNeverTouched() {
        final RealmWalletPepper peppers = mock(RealmWalletPepper.class);

        final WalletSubject subject = new WalletSubjectResolver(peppers).resolve(REALM,
                sdJwt(pid("Erika", "M")), NUMBER_ONLY, DEFAULT_CLAIMS);

        assertThat(subject).isEqualTo(new WalletSubject.Unavailable(WalletSubject.Reason.WEAK_SUBJECT_NOT_ACKNOWLEDGED));
        assertThat(subject.errorCode()).isEqualTo(WalletErrorCode.SUBJECT_UNAVAILABLE);
        assertThat(((WalletSubject.Unavailable) subject).reason().code())
                .isEqualTo("wallet.subject_unavailable.weak_subject_not_acknowledged");
        verifyNoInteractions(peppers);
    }

    @Test
    void tupleStrategyWithoutAcknowledgement_isRefused() {
        assertThat(resolve(PEPPER, sdJwt(pid("Erika", "M")), TUPLE_NOT_ACKNOWLEDGED))
                .isEqualTo(new WalletSubject.Unavailable(WalletSubject.Reason.WEAK_SUBJECT_NOT_ACKNOWLEDGED));
    }

    @Test
    void strategyNone_isRefused() {
        assertThat(resolve(PEPPER, sdJwt(withNumber(pid("E", "M"), "NL", "123")),
                new WalletProviderConfig.Subject(WalletProviderConfig.Subject.Strategy.NONE, true)))
                .isEqualTo(new WalletSubject.Unavailable(WalletSubject.Reason.STRATEGY_NOT_SUPPORTED));
    }

    @Test
    void numberAbsent_flagOn_givesTheTuple() {
        assertThat(resolve(PEPPER, sdJwt(pid("Erika", "M")), NUMBER_ELSE_LINK))
                .isInstanceOf(WalletSubject.Tuple.class);
        assertThat(resolve(PEPPER, sdJwt(pid("Erika", "M")), TUPLE_ACKNOWLEDGED))
                .isInstanceOf(WalletSubject.Tuple.class);
    }

    @Test
    void everyConfiguredTupleFieldIsRequired_neverAShorterTuple() {
        for (final String field : List.of("given_name", "family_name", "birthdate", "issuing_country")) {
            final Map<String, Object> claims = pid("Erika", "M");
            claims.remove(field);

            assertThat(resolve(PEPPER, sdJwt(claims), NUMBER_ELSE_LINK)).as(field)
                    .isEqualTo(new WalletSubject.Unavailable(WalletSubject.Reason.MISSING_IDENTITY_ATTRIBUTES));
        }
    }

    @Test
    void anEmptyFieldIsMissing_notAnEmptyValue() {
        final Map<String, Object> blank = pid("Erika", "M");
        blank.put("given_name", "  \t ");

        assertThat(resolve(PEPPER, sdJwt(blank), NUMBER_ELSE_LINK))
                .isEqualTo(new WalletSubject.Unavailable(WalletSubject.Reason.MISSING_IDENTITY_ATTRIBUTES));
    }

    @Test
    void tupleFieldsAreSeparatedUnambiguously() {
        final String abC = subjectOf(resolve(PEPPER, sdJwt(pid("ab", "c")), NUMBER_ELSE_LINK));
        final String aBc = subjectOf(resolve(PEPPER, sdJwt(pid("a", "bc")), NUMBER_ELSE_LINK));

        assertThat(abC).isNotEqualTo(aBc);
    }

    @Test
    void tupleIsNormalised_nfcTrimLowerCaseSingleSpaces() {
        final String nfd = "Renée  Marie";            // e + combining acute, two spaces

        final String a = subjectOf(resolve(PEPPER, sdJwt(withNumber(pid(nfd, " Muller "), "nl", null)),
                NUMBER_ELSE_LINK));
        final String b = subjectOf(resolve(PEPPER, sdJwt(withNumber(pid("RENÉE Marie", "muller"), "NL", null)),
                NUMBER_ELSE_LINK));

        assertThat(a).isEqualTo(b);
    }

    @Test
    void nbspAndTabCollapseToOneSpace() {
        final String plain = subjectOf(resolve(PEPPER, sdJwt(pid("Anna Maria", "M")), NUMBER_ELSE_LINK));

        assertThat(subjectOf(resolve(PEPPER, sdJwt(pid("Anna Maria", "M")), NUMBER_ELSE_LINK))).isEqualTo(plain);
        assertThat(subjectOf(resolve(PEPPER, sdJwt(pid("Anna\t \tMaria", "M")), NUMBER_ELSE_LINK))).isEqualTo(plain);
    }

    @Test
    void sharpSIsNotFoldedToSs() {
        assertThat(subjectOf(resolve(PEPPER, sdJwt(pid("Erika", "Strauß")), NUMBER_ELSE_LINK)))
                .isNotEqualTo(subjectOf(resolve(PEPPER, sdJwt(pid("Erika", "Strauss")), NUMBER_ELSE_LINK)));
    }

    @Test
    void tupleDiffersByEveryField() {
        final String base = subjectOf(resolve(PEPPER, sdJwt(pid("Erika", "M")), NUMBER_ELSE_LINK));
        final Map<String, Object> otherBirthdate = pid("Erika", "M");
        otherBirthdate.put("birthdate", "1964-08-13");

        assertThat(subjectOf(resolve(PEPPER, sdJwt(otherBirthdate), NUMBER_ELSE_LINK))).isNotEqualTo(base);
        assertThat(subjectOf(resolve(PEPPER, sdJwt(withNumber(pid("Erika", "M"), "DE", null)), NUMBER_ELSE_LINK)))
                .isNotEqualTo(base);
    }

    // ------------------------------------------------------------------------------------------- place of birth

    private static Map<String, Object> bornIn(final Map<String, String> placeOfBirth) {
        final Map<String, Object> claims = pid("Erika", "M");
        claims.put("place_of_birth", placeOfBirth);
        return claims;
    }

    @Test
    void placeOfBirth_isInTheTupleOnlyWhenConfigured() {
        final WalletSubjectResolver resolver = resolver(PEPPER);
        final Map<String, Object> berlin = bornIn(Map.of("country", "DE", "region", "Berlin", "locality", "Berlin"));

        // not configured: place_of_birth is ignored, whatever the presentation carries
        assertThat(subjectOf(resolver.resolve(REALM, sdJwt(berlin), NUMBER_ELSE_LINK, DEFAULT_CLAIMS)))
                .isEqualTo(subjectOf(resolver.resolve(REALM, sdJwt(pid("Erika", "M")), NUMBER_ELSE_LINK,
                        DEFAULT_CLAIMS)));
        // configured: it changes the tuple
        assertThat(subjectOf(resolver.resolve(REALM, sdJwt(berlin), NUMBER_ELSE_LINK, WITH_PLACE_OF_BIRTH)))
                .isNotEqualTo(subjectOf(resolver.resolve(REALM, sdJwt(berlin), NUMBER_ELSE_LINK, DEFAULT_CLAIMS)));
    }

    @Test
    void placeOfBirthConfigured_everyPartCounts() {
        final WalletSubjectResolver resolver = resolver(PEPPER);
        final String berlin = subjectOf(resolver.resolve(REALM,
                sdJwt(bornIn(Map.of("country", "DE", "region", "Berlin", "locality", "Berlin"))), NUMBER_ELSE_LINK,
                WITH_PLACE_OF_BIRTH));

        assertThat(subjectOf(resolver.resolve(REALM,
                sdJwt(bornIn(Map.of("country", "DE", "region", "Berlin", "locality", "Pankow"))), NUMBER_ELSE_LINK,
                WITH_PLACE_OF_BIRTH))).isNotEqualTo(berlin);
        // a part that is missing is not the same as a part that is present
        assertThat(subjectOf(resolver.resolve(REALM,
                sdJwt(bornIn(Map.of("country", "DE", "locality", "Berlin"))), NUMBER_ELSE_LINK,
                WITH_PLACE_OF_BIRTH))).isNotEqualTo(berlin);
    }

    @Test
    void placeOfBirthConfigured_anObjectWithOnlyLocality_encodesTheMissingPartsAsEmpty() {
        // ruling: missing parts are empty strings, fixed order:
        // ... + "place_of_birth.country=0:;place_of_birth.region=0:;place_of_birth.locality=6:berlin;"
        assertThat(subjectOf(resolver(PEPPER).resolve(REALM, sdJwt(bornIn(Map.of("locality", "Berlin"))),
                NUMBER_ELSE_LINK, WITH_PLACE_OF_BIRTH)))
                .isEqualTo("0a875dca659312c2fa3d9856a7cfa5f2edfca06ae27abb4c54073529c411808f");
    }

    @Test
    void placeOfBirthConfigured_noObjectOrAnEmptyOne_isSubjectUnavailable() {
        final WalletSubjectResolver resolver = resolver(PEPPER);

        assertThat(resolver.resolve(REALM, sdJwt(pid("Erika", "M")), NUMBER_ELSE_LINK, WITH_PLACE_OF_BIRTH))
                .isEqualTo(new WalletSubject.Unavailable(WalletSubject.Reason.MISSING_IDENTITY_ATTRIBUTES));
        assertThat(resolver.resolve(REALM, sdJwt(bornIn(Map.of())), NUMBER_ELSE_LINK, WITH_PLACE_OF_BIRTH))
                .isEqualTo(new WalletSubject.Unavailable(WalletSubject.Reason.MISSING_IDENTITY_ATTRIBUTES));
        assertThat(resolver.resolve(REALM, sdJwt(bornIn(Map.of("locality", " "))), NUMBER_ELSE_LINK,
                WITH_PLACE_OF_BIRTH))
                .isEqualTo(new WalletSubject.Unavailable(WalletSubject.Reason.MISSING_IDENTITY_ATTRIBUTES));
    }

    // ------------------------------------------------------------------------------------------- logging

    @Test
    void onlyTheSubjectHashIsLogged_neverTheNumberOrTheTuple() {
        try (LogCapture log = LogCapture.of(WalletSubjectResolver.class)) {
            final String admin = subjectOf(resolve(PEPPER,
                    sdJwt(withNumber(pid("Erika", "Mustermann"), "NL", "123456789")), NUMBER_ONLY));
            final String tuple = subjectOf(resolve(PEPPER, sdJwt(pid("Erika", "Mustermann")), NUMBER_ELSE_LINK));

            assertThat(log.text()).contains(admin).contains(tuple).doesNotContain("123456789")
                    .doesNotContain("Erika").doesNotContain("Mustermann").doesNotContain("1964");
        }
    }
}
