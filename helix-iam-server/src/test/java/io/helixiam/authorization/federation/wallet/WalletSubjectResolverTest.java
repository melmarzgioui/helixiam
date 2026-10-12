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
 */
class WalletSubjectResolverTest {

    private static final String SD_JWT = "dc+sd-jwt";
    private static final String MDOC = "mso_mdoc";
    private static final String NS = "eu.europa.ec.eudi.pid.1";
    private static final String REALM = "acme";
    private static final byte[] PEPPER = filled((byte) 7);
    private static final byte[] OTHER_PEPPER = filled((byte) 9);

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

    private static Map<String, Object> pid(final String given, final String family) {
        final Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("given_name", given);
        claims.put("family_name", family);
        claims.put("birthdate", "1964-08-12");
        return claims;
    }

    private static Map<String, Object> withNumber(final Map<String, Object> claims, final String country,
            final String number) {
        final Map<String, Object> out = new LinkedHashMap<>(claims);
        if (country != null) {
            out.put("issuing_country", country);
        }
        if (number != null) {
            out.put("personal_administrative_number", number);
        }
        return out;
    }

    private static MatchedPresentations sdJwt(final Map<String, Object> claims) {
        return new MatchedPresentations(List.of(new VerifiedPresentation(SD_JWT, "urn:eudi:pid:1", claims,
                "CN=PID Issuer", "1f", "VALID")), Set.of());
    }

    private static VerifiedPresentation mdocPresentation(final Map<String, Object> elements) {
        return new VerifiedPresentation(MDOC, NS, Map.of(NS, elements), "CN=PID Issuer", "2f", "VALID");
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

    // ------------------------------------------------------------------------------------------- administrative number

    @Test
    void numberPresent_givesAdminNumber_hmacOfCountryColonNumber() throws Exception {
        final WalletSubject subject = resolver(PEPPER).resolve(REALM,
                sdJwt(withNumber(pid("Erika", "Mustermann"), "NL", "123456789")), NUMBER_ONLY);

        assertThat(subject).isInstanceOf(WalletSubject.AdminNumber.class);
        assertThat(subjectOf(subject)).isEqualTo(hmacHex(PEPPER, "NL:123456789")).matches("[0-9a-f]{64}");
    }

    @Test
    void sameNumberDifferentCountry_givesDifferentSubjects() {
        final WalletSubjectResolver resolver = resolver(PEPPER);

        final String nl = subjectOf(resolver.resolve(REALM, sdJwt(withNumber(pid("Erika", "M"), "NL", "123")),
                NUMBER_ONLY));
        final String de = subjectOf(resolver.resolve(REALM, sdJwt(withNumber(pid("Erika", "M"), "DE", "123")),
                NUMBER_ONLY));

        assertThat(nl).isNotEqualTo(de);
    }

    @Test
    void differentPepper_givesDifferentSubject() {
        final MatchedPresentations withNumber = sdJwt(withNumber(pid("Erika", "M"), "NL", "123"));
        final MatchedPresentations without = sdJwt(withNumber(pid("Erika", "M"), "NL", null));

        assertThat(subjectOf(resolver(PEPPER).resolve(REALM, withNumber, NUMBER_ONLY)))
                .isNotEqualTo(subjectOf(resolver(OTHER_PEPPER).resolve(REALM, withNumber, NUMBER_ONLY)));
        assertThat(subjectOf(resolver(PEPPER).resolve(REALM, without, NUMBER_ELSE_LINK)))
                .isNotEqualTo(subjectOf(resolver(OTHER_PEPPER).resolve(REALM, without, NUMBER_ELSE_LINK)));
    }

    @Test
    void theNumberIsTheSubject_whateverTheNamesSay() {
        final WalletSubjectResolver resolver = resolver(PEPPER);

        assertThat(subjectOf(resolver.resolve(REALM, sdJwt(withNumber(pid("Erika", "Mustermann"), "NL", "123")),
                NUMBER_ONLY))).isEqualTo(subjectOf(resolver.resolve(REALM,
                sdJwt(withNumber(pid("Erika", "Gabler"), "NL", "123")), NUMBER_ONLY)));
    }

    @Test
    void numberPresent_winsUnderTheTupleStrategyToo() {
        assertThat(resolver(PEPPER).resolve(REALM, sdJwt(withNumber(pid("Erika", "M"), "NL", "123")),
                TUPLE_ACKNOWLEDGED)).isInstanceOf(WalletSubject.AdminNumber.class);
    }

    @Test
    void countryCaseAndSurroundingSpaceDoNotChangeTheAdminSubject() {
        final WalletSubjectResolver resolver = resolver(PEPPER);

        assertThat(subjectOf(resolver.resolve(REALM, sdJwt(withNumber(pid("E", "M"), " nl ", " 123 ")),
                NUMBER_ONLY))).isEqualTo(subjectOf(resolver.resolve(REALM,
                sdJwt(withNumber(pid("E", "M"), "NL", "123")), NUMBER_ONLY)));
    }

    @Test
    void numberFromAnMdocPresentationIsUsed() throws Exception {
        final Map<String, Object> elements = new LinkedHashMap<>();
        elements.put("given_name", "Erika");
        elements.put("family_name", "Mustermann");
        elements.put("birth_date", "1964-08-12");
        elements.put("issuing_country", "NL");
        elements.put("personal_administrative_number", "123456789");

        final WalletSubject subject = resolver(PEPPER).resolve(REALM,
                new MatchedPresentations(List.of(mdocPresentation(elements)), Set.of()), NUMBER_ONLY);

        assertThat(subjectOf(subject)).isEqualTo(hmacHex(PEPPER, "NL:123456789"));
    }

    @Test
    void bothFormatsDisagreeingOnTheNumber_isRefused() {
        final Map<String, Object> elements = new LinkedHashMap<>();
        elements.put("given_name", "Erika");
        elements.put("family_name", "Mustermann");
        elements.put("birth_date", "1964-08-12");
        elements.put("issuing_country", "NL");
        elements.put("personal_administrative_number", "999");
        final MatchedPresentations both = new MatchedPresentations(List.of(
                new VerifiedPresentation(SD_JWT, "urn:eudi:pid:1",
                        withNumber(pid("Erika", "Mustermann"), "NL", "123"), "CN=PID Issuer", "1f", "VALID"),
                mdocPresentation(elements)), Set.of());

        assertThatThrownBy(() -> resolver(PEPPER).resolve(REALM, both, NUMBER_ONLY))
                .isInstanceOf(WalletVerificationException.class)
                .satisfies(e -> assertThat(((WalletVerificationException) e).code())
                        .isEqualTo(WalletErrorCode.INVALID_RESPONSE))
                .hasMessageNotContaining("123").hasMessageNotContaining("999");
    }

    @Test
    void aNumberWithoutACountryIsNotUsed() {
        assertThat(resolver(PEPPER).resolve(REALM, sdJwt(withNumber(pid("E", "M"), null, "123")), NUMBER_ONLY))
                .isEqualTo(new WalletSubject.Unavailable(WalletSubject.Reason.WEAK_SUBJECT_NOT_ACKNOWLEDGED));
        assertThat(resolver(PEPPER).resolve(REALM, sdJwt(withNumber(pid("E", "M"), null, "123")), NUMBER_ELSE_LINK))
                .isInstanceOf(WalletSubject.Tuple.class);
    }

    @Test
    void aBlankNumberCountsAsAbsent() {
        assertThat(resolver(PEPPER).resolve(REALM, sdJwt(withNumber(pid("E", "M"), "NL", "  ")), NUMBER_ELSE_LINK))
                .isInstanceOf(WalletSubject.Tuple.class);
    }

    // ------------------------------------------------------------------------------------------- no number

    @Test
    void numberAbsent_flagOff_isRefusedWithAReason_andThePepperIsNeverTouched() {
        final RealmWalletPepper peppers = mock(RealmWalletPepper.class);

        final WalletSubject subject = new WalletSubjectResolver(peppers).resolve(REALM,
                sdJwt(withNumber(pid("Erika", "M"), "NL", null)), NUMBER_ONLY);

        assertThat(subject).isEqualTo(new WalletSubject.Unavailable(WalletSubject.Reason.WEAK_SUBJECT_NOT_ACKNOWLEDGED));
        assertThat(subject.errorCode()).isEqualTo(WalletErrorCode.SUBJECT_UNAVAILABLE);
        assertThat(((WalletSubject.Unavailable) subject).reason().code())
                .isEqualTo("wallet.subject_unavailable.weak_subject_not_acknowledged");
        verifyNoInteractions(peppers);
    }

    @Test
    void tupleStrategyWithoutAcknowledgement_isRefused() {
        assertThat(resolver(PEPPER).resolve(REALM, sdJwt(pid("Erika", "M")), TUPLE_NOT_ACKNOWLEDGED))
                .isEqualTo(new WalletSubject.Unavailable(WalletSubject.Reason.WEAK_SUBJECT_NOT_ACKNOWLEDGED));
    }

    @Test
    void strategyNone_isRefused() {
        assertThat(resolver(PEPPER).resolve(REALM, sdJwt(withNumber(pid("E", "M"), "NL", "123")),
                new WalletProviderConfig.Subject(WalletProviderConfig.Subject.Strategy.NONE, true)))
                .isEqualTo(new WalletSubject.Unavailable(WalletSubject.Reason.STRATEGY_NOT_SUPPORTED));
    }

    @Test
    void numberAbsent_flagOn_givesTheTuple() {
        assertThat(resolver(PEPPER).resolve(REALM, sdJwt(withNumber(pid("Erika", "M"), "NL", null)),
                NUMBER_ELSE_LINK)).isInstanceOf(WalletSubject.Tuple.class);
        assertThat(resolver(PEPPER).resolve(REALM, sdJwt(pid("Erika", "M")), TUPLE_ACKNOWLEDGED))
                .isInstanceOf(WalletSubject.Tuple.class);
    }

    @Test
    void tupleNeedsNamesAndBirthdate() {
        final Map<String, Object> claims = pid("Erika", "M");
        claims.remove("given_name");

        assertThat(resolver(PEPPER).resolve(REALM, sdJwt(claims), NUMBER_ELSE_LINK))
                .isEqualTo(new WalletSubject.Unavailable(WalletSubject.Reason.MISSING_IDENTITY_ATTRIBUTES));
    }

    @Test
    void tupleFieldsAreSeparatedUnambiguously() {
        final WalletSubjectResolver resolver = resolver(PEPPER);

        final String abC = subjectOf(resolver.resolve(REALM, sdJwt(pid("ab", "c")), NUMBER_ELSE_LINK));
        final String aBc = subjectOf(resolver.resolve(REALM, sdJwt(pid("a", "bc")), NUMBER_ELSE_LINK));

        assertThat(abC).isNotEqualTo(aBc);
    }

    @Test
    void tupleIsNormalised_nfcTrimLowerCaseSingleSpaces() {
        final WalletSubjectResolver resolver = resolver(PEPPER);
        final String nfd = "Renée  Marie";            // e + combining acute, two spaces

        final String a = subjectOf(resolver.resolve(REALM, sdJwt(withNumber(pid(nfd, " Muller "), "nl", null)),
                NUMBER_ELSE_LINK));
        final String b = subjectOf(resolver.resolve(REALM, sdJwt(withNumber(pid("RENÉE Marie", "muller"), "NL", null)),
                NUMBER_ELSE_LINK));

        assertThat(a).isEqualTo(b);
    }

    @Test
    void tupleDiffersFromTheAdminSubjectAndByEveryField() {
        final WalletSubjectResolver resolver = resolver(PEPPER);
        final String base = subjectOf(resolver.resolve(REALM, sdJwt(pid("Erika", "M")), NUMBER_ELSE_LINK));
        final Map<String, Object> otherBirthdate = pid("Erika", "M");
        otherBirthdate.put("birthdate", "1964-08-13");

        assertThat(subjectOf(resolver.resolve(REALM, sdJwt(otherBirthdate), NUMBER_ELSE_LINK))).isNotEqualTo(base);
        assertThat(subjectOf(resolver.resolve(REALM, sdJwt(withNumber(pid("Erika", "M"), "NL", null)),
                NUMBER_ELSE_LINK))).isNotEqualTo(base);
    }

    @Test
    void placeOfBirthPartsThatArePresentAreIncluded() {
        final WalletSubjectResolver resolver = resolver(PEPPER);
        final Map<String, Object> berlin = pid("Erika", "M");
        berlin.put("place_of_birth", Map.of("country", "DE", "locality", "Berlin"));
        final Map<String, Object> hamburg = pid("Erika", "M");
        hamburg.put("place_of_birth", Map.of("country", "DE", "locality", "Hamburg"));
        final Map<String, Object> localityAsRegion = pid("Erika", "M");
        localityAsRegion.put("place_of_birth", Map.of("country", "DE", "region", "Berlin"));

        final String b = subjectOf(resolver.resolve(REALM, sdJwt(berlin), NUMBER_ELSE_LINK));
        assertThat(subjectOf(resolver.resolve(REALM, sdJwt(hamburg), NUMBER_ELSE_LINK))).isNotEqualTo(b);
        assertThat(subjectOf(resolver.resolve(REALM, sdJwt(localityAsRegion), NUMBER_ELSE_LINK))).isNotEqualTo(b);
        assertThat(subjectOf(resolver.resolve(REALM, sdJwt(pid("Erika", "M")), NUMBER_ELSE_LINK))).isNotEqualTo(b);
    }

    // ------------------------------------------------------------------------------------------- logging

    @Test
    void onlyTheSubjectHashIsLogged_neverTheNumberOrTheTuple() {
        try (LogCapture log = LogCapture.of(WalletSubjectResolver.class)) {
            final String admin = subjectOf(resolver(PEPPER).resolve(REALM,
                    sdJwt(withNumber(pid("Erika", "Mustermann"), "NL", "123456789")), NUMBER_ONLY));
            final String tuple = subjectOf(resolver(PEPPER).resolve(REALM,
                    sdJwt(withNumber(pid("Erika", "Mustermann"), "NL", null)), NUMBER_ELSE_LINK));

            assertThat(log.text()).contains(admin).contains(tuple).doesNotContain("123456789")
                    .doesNotContain("Erika").doesNotContain("Mustermann").doesNotContain("1964");
        }
    }
}
