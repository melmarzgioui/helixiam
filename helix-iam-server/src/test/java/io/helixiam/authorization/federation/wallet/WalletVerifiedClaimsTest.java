/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.wallet;

import org.junit.jupiter.api.Test;

import java.time.LocalDate;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/** The verify-only release rules: which claims may be released, and what a release contains. */
class WalletVerifiedClaimsTest {

    private static final LocalDate TODAY = LocalDate.of(2026, 10, 15);

    private static Map<String, String> attributes() {
        final Map<String, String> a = new LinkedHashMap<>();
        a.put("given_name", "Ada");
        a.put("family_name", "Lovelace");
        a.put("birthdate", "2008-10-15");
        a.put("nationalities", "NL,DE");
        a.put("place_of_birth.country", "NL");
        a.put("place_of_birth.locality", "Arnhem");
        a.put("helix_wallet_format", "dc+sd-jwt");
        a.put("helix_wallet_issuer", "CN=PID Issuer");
        return a;
    }

    @Test
    void problem_acceptsRequestedMappedClaimsAndAgeThresholds() {
        assertThat(WalletVerifiedClaims.problem(List.of("birthdate", "nationalities", "place_of_birth"),
                List.of("age_over_18", "nationalities", "place_of_birth", "age_over_150", "age_over_1"))).isEmpty();
        assertThat(WalletVerifiedClaims.problem(List.of("given_name"), List.of())).isEmpty();
    }

    @Test
    void problem_refusesWhatIsNotRequestedNotMappedOrMalformed() {
        assertThat(WalletVerifiedClaims.problem(List.of("birthdate"), List.of("given_name"))).isPresent();
        assertThat(WalletVerifiedClaims.problem(List.of("personal_administrative_number"),
                List.of("personal_administrative_number"))).isPresent();
        assertThat(WalletVerifiedClaims.problem(List.of("picture"), List.of("picture"))).as("not mapped").isPresent();
        assertThat(WalletVerifiedClaims.problem(List.of("nationalities"), List.of("age_over_18"))).isPresent();
        assertThat(WalletVerifiedClaims.problem(List.of("birthdate"), List.of("age_over_0"))).isPresent();
        assertThat(WalletVerifiedClaims.problem(List.of("birthdate"), List.of("age_over_151"))).isPresent();
        assertThat(WalletVerifiedClaims.problem(List.of("birthdate"), List.of("age_over_018"))).isPresent();
        assertThat(WalletVerifiedClaims.problem(List.of("birthdate"), List.of("birthdate", "birthdate"))).isPresent();
        assertThat(WalletVerifiedClaims.problem(List.of("birthdate"), java.util.Arrays.asList((String) null)))
                .isPresent();
        assertThat(WalletVerifiedClaims.problem(List.of("birthdate"), List.of(" "))).isPresent();
    }

    @Test
    void release_containsExactlyTheListedClaims_andDerivesAgesWithoutTheBirthdate() {
        final Map<String, Object> released = WalletVerifiedClaims.release(attributes(),
                List.of("age_over_18", "age_over_21", "nationalities"), TODAY);
        assertThat(released).containsExactly(Map.entry("age_over_18", true), Map.entry("age_over_21", false),
                Map.entry("nationalities", "NL,DE"));
        assertThat(released).isInstanceOf(LinkedHashMap.class);
    }

    @Test
    void release_ofAnObjectClaim_takesItsDottedMembers_andSkipsWhatThePidLacks() {
        final Map<String, Object> released = WalletVerifiedClaims.release(attributes(),
                List.of("place_of_birth", "issuing_country"), TODAY);
        assertThat(released).containsExactly(Map.entry("place_of_birth.country", "NL"),
                Map.entry("place_of_birth.locality", "Arnhem"));
    }

    @Test
    void ageOver_isFalseTheDayBefore_trueOnTheBirthday_andAbsentWithoutAReadableBirthdate() {
        final Map<String, String> a = attributes();
        assertThat(WalletVerifiedClaims.release(a, List.of("age_over_18"), TODAY.minusDays(1)))
                .containsEntry("age_over_18", false);
        assertThat(WalletVerifiedClaims.release(a, List.of("age_over_18"), TODAY)).containsEntry("age_over_18", true);
        a.put("birthdate", "not a date");
        assertThat(WalletVerifiedClaims.release(a, List.of("age_over_18"), TODAY)).isEmpty();
        a.remove("birthdate");
        assertThat(WalletVerifiedClaims.release(a, List.of("age_over_18"), TODAY)).isEmpty();
    }

    @Test
    void releasedNames_areTheKeys() {
        assertThat(WalletVerifiedClaims.release(attributes(), List.of(), TODAY)).isEmpty();
    }

    @Test
    void aTwentyNinthOfFebruaryBirthday_isReachedOnTheFirstOfMarchInANonLeapYear() {
        final Map<String, String> a = new LinkedHashMap<>(Map.of("birthdate", "2008-02-29"));
        assertThat(WalletVerifiedClaims.release(a, List.of("age_over_18"), LocalDate.of(2026, 2, 28)))
                .containsEntry("age_over_18", false);
        assertThat(WalletVerifiedClaims.release(a, List.of("age_over_18"), LocalDate.of(2026, 3, 1)))
                .containsEntry("age_over_18", true);
        assertThat(WalletVerifiedClaims.release(a, List.of("age_over_16"), LocalDate.of(2024, 2, 29)))
                .as("in a leap year the day itself").containsEntry("age_over_16", true);
    }

    @Test
    void today_isTheDateInTheFurthestBehindZone_soAnAgeIsNeverReachedEarly() {
        // 2026-10-15T11:00Z is still 2026-10-14 at UTC-12
        final java.time.Clock clock = java.time.Clock.fixed(java.time.Instant.parse("2026-10-15T11:00:00Z"),
                java.time.ZoneOffset.UTC);
        assertThat(WalletVerifiedClaims.today(clock)).isEqualTo(LocalDate.of(2026, 10, 14));
        final Map<String, String> a = new LinkedHashMap<>(Map.of("birthdate", "2008-10-15"));
        assertThat(WalletVerifiedClaims.release(a, List.of("age_over_18"), WalletVerifiedClaims.today(clock)))
                .containsEntry("age_over_18", false);
    }
}
