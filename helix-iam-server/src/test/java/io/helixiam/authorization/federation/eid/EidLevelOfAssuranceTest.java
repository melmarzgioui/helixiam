/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.eid;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Helix IAM E6: level-of-assurance handling for the EU/NL eID schemes. Each scheme expresses LoA as
 * a SAML {@code AuthnContextClassRef} URN with its own ordered ladder (eIDAS low/substantial/high,
 * DigiD Basis/Midden/Substantieel/Hoog, eHerkenning LoA2/2+/3/4). The broker enforces a minimum, so
 * the core operation is "does the asserted level meet (≥) the required one" — comparing rungs across
 * the scheme's ladder, independent of the exact URN strings.
 */
class EidLevelOfAssuranceTest {

    // --- eIDAS -------------------------------------------------------------------------------------

    @Test
    void eidasUrnsMapToTheirRungInOrder() {
        assertThat(EidLevelOfAssurance.rung(EidScheme.EIDAS, "http://eidas.europa.eu/LoA/low")).isEqualTo(1);
        assertThat(EidLevelOfAssurance.rung(EidScheme.EIDAS, "http://eidas.europa.eu/LoA/substantial")).isEqualTo(2);
        assertThat(EidLevelOfAssurance.rung(EidScheme.EIDAS, "http://eidas.europa.eu/LoA/high")).isEqualTo(3);
    }

    @Test
    void eidasHighMeetsASubstantialMinimumButLowDoesNot() {
        assertThat(EidLevelOfAssurance.meetsMinimum(EidScheme.EIDAS,
                "http://eidas.europa.eu/LoA/high", "http://eidas.europa.eu/LoA/substantial")).isTrue();
        assertThat(EidLevelOfAssurance.meetsMinimum(EidScheme.EIDAS,
                "http://eidas.europa.eu/LoA/low", "http://eidas.europa.eu/LoA/substantial")).isFalse();
    }

    // --- DigiD -------------------------------------------------------------------------------------

    @Test
    void digidUrnsMapToTheirRungInOrder() {
        assertThat(EidLevelOfAssurance.rung(EidScheme.DIGID, "urn:nl-eid-gdi:1.0:LoA:Low")).isEqualTo(1);         // Basis
        assertThat(EidLevelOfAssurance.rung(EidScheme.DIGID, "urn:nl-eid-gdi:1.0:LoA:Midden")).isEqualTo(2);      // Midden
        assertThat(EidLevelOfAssurance.rung(EidScheme.DIGID, "urn:nl-eid-gdi:1.0:LoA:Substantial")).isEqualTo(3); // Substantieel
        assertThat(EidLevelOfAssurance.rung(EidScheme.DIGID, "urn:nl-eid-gdi:1.0:LoA:High")).isEqualTo(4);        // Hoog
    }

    @Test
    void digidSubstantieelDoesNotMeetAHoogMinimum() {
        assertThat(EidLevelOfAssurance.meetsMinimum(EidScheme.DIGID,
                "urn:nl-eid-gdi:1.0:LoA:Substantial", "urn:nl-eid-gdi:1.0:LoA:High")).isFalse();
    }

    // --- eHerkenning -------------------------------------------------------------------------------

    @Test
    void eherkenningUrnsMapToTheirRung() {
        assertThat(EidLevelOfAssurance.rung(EidScheme.EHERKENNING, "urn:etoegang:core:assurance-class:loa2")).isEqualTo(2);
        assertThat(EidLevelOfAssurance.rung(EidScheme.EHERKENNING, "urn:etoegang:core:assurance-class:loa3")).isEqualTo(3);
        assertThat(EidLevelOfAssurance.rung(EidScheme.EHERKENNING, "urn:etoegang:core:assurance-class:loa4")).isEqualTo(4);
        assertThat(EidLevelOfAssurance.meetsMinimum(EidScheme.EHERKENNING,
                "urn:etoegang:core:assurance-class:loa3", "urn:etoegang:core:assurance-class:loa3")).isTrue();
    }

    // --- robustness --------------------------------------------------------------------------------

    @Test
    void unknownClassRefIsRungZeroAndNeverMeetsAMinimum() {
        assertThat(EidLevelOfAssurance.rung(EidScheme.EIDAS, "urn:something:unrecognised")).isZero();
        assertThat(EidLevelOfAssurance.meetsMinimum(EidScheme.EIDAS,
                "urn:something:unrecognised", "http://eidas.europa.eu/LoA/low")).isFalse();
    }

    @Test
    void aNullAssertedLevelNeverMeetsAMinimum() {
        assertThat(EidLevelOfAssurance.meetsMinimum(EidScheme.DIGID, null,
                "urn:nl-eid-gdi:1.0:LoA:Low")).isFalse();
    }

    @Test
    void aBlankMinimumIsAlwaysMet() {
        // No minimum configured -> any successfully-asserted level is acceptable.
        assertThat(EidLevelOfAssurance.meetsMinimum(EidScheme.DIGID,
                "urn:nl-eid-gdi:1.0:LoA:Low", null)).isTrue();
        assertThat(EidLevelOfAssurance.meetsMinimum(EidScheme.DIGID,
                "urn:nl-eid-gdi:1.0:LoA:Low", "  ")).isTrue();
    }
    // --- fail closed on an unrecognised minimum ----------------------------------------------------

    @Test
    void anUnrecognisedMinimumIsNeverMet() {
        // A typo or another scheme's URN must not silently lower the bar to "anything goes".
        assertThat(EidLevelOfAssurance.meetsMinimum(EidScheme.EIDAS,
                "http://eidas.europa.eu/LoA/high", "urn:something:unrecognised")).isFalse();
        assertThat(EidLevelOfAssurance.meetsMinimum(EidScheme.DIGID,
                "urn:nl-eid-gdi:1.0:LoA:High", "http://eidas.europa.eu/LoA/low")).isFalse();
        assertThat(EidLevelOfAssurance.meetsMinimum(EidScheme.DIGID,
                "urn:nl-eid-gdi:1.0:LoA:High", "urn:nl-eid-gdi:1.0:LoA:Substantieel")).isFalse();
    }

    @Test
    void theConsoleKeywordsAreRecognisedMinimums() {
        // The admin console stores the scheme's short keyword (loa1..loa4, low/substantial/high).
        assertThat(EidLevelOfAssurance.canonicalMinimum(EidScheme.DIGID, "loa3"))
                .isEqualTo("urn:nl-eid-gdi:1.0:LoA:Substantial");
        assertThat(EidLevelOfAssurance.canonicalMinimum(EidScheme.EHERKENNING, "LoA3"))
                .isEqualTo("urn:etoegang:core:assurance-class:loa3");
        assertThat(EidLevelOfAssurance.canonicalMinimum(EidScheme.EIDAS, "substantial"))
                .isEqualTo("http://eidas.europa.eu/LoA/substantial");
        assertThat(EidLevelOfAssurance.canonicalMinimum(EidScheme.EIDAS, "http://eidas.europa.eu/LoA/high"))
                .isEqualTo("http://eidas.europa.eu/LoA/high");
        assertThat(EidLevelOfAssurance.meetsMinimum(EidScheme.DIGID,
                "urn:nl-eid-gdi:1.0:LoA:High", "loa3")).isTrue();
        assertThat(EidLevelOfAssurance.meetsMinimum(EidScheme.DIGID,
                "urn:nl-eid-gdi:1.0:LoA:Midden", "loa3")).isFalse();
    }

    @Test
    void anUnknownMinimumHasNoCanonicalForm_andABlankOneIsNoMinimum() {
        assertThat(EidLevelOfAssurance.canonicalMinimum(EidScheme.DIGID, "loa9")).isNull();
        assertThat(EidLevelOfAssurance.canonicalMinimum(EidScheme.EIDAS, "loa3")).isNull();
        assertThat(EidLevelOfAssurance.isValidMinimum(EidScheme.DIGID, "loa9")).isFalse();
        assertThat(EidLevelOfAssurance.isValidMinimum(EidScheme.DIGID, "loa1")).isTrue();
        assertThat(EidLevelOfAssurance.isValidMinimum(EidScheme.DIGID, null)).isTrue();
        assertThat(EidLevelOfAssurance.isValidMinimum(EidScheme.DIGID, "  ")).isTrue();
    }

    // --- classic DigiD (Koppelvlak SAML) AuthnContextClassRefs ---------------------------------------

    private static final String PPT = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport";
    private static final String MOBILE_2F = "urn:oasis:names:tc:SAML:2.0:ac:classes:MobileTwoFactorContract";
    private static final String SMARTCARD = "urn:oasis:names:tc:SAML:2.0:ac:classes:Smartcard";
    private static final String SMARTCARD_PKI = "urn:oasis:names:tc:SAML:2.0:ac:classes:SmartcardPKI";

    @Test
    void classicDigidClassesSitOnTheDigidLadder() {
        assertThat(EidLevelOfAssurance.rung(EidScheme.DIGID, PPT)).isEqualTo(1);           // Basis
        assertThat(EidLevelOfAssurance.rung(EidScheme.DIGID, MOBILE_2F)).isEqualTo(2);     // Midden
        assertThat(EidLevelOfAssurance.rung(EidScheme.DIGID, SMARTCARD)).isEqualTo(3);     // Substantieel
        assertThat(EidLevelOfAssurance.rung(EidScheme.DIGID, SMARTCARD_PKI)).isEqualTo(4); // Hoog
    }

    @Test
    void classicDigidClassesAgainstConsoleStoredMinimums() {
        // loa3 (Substantieel), the console default
        assertThat(EidLevelOfAssurance.meetsMinimum(EidScheme.DIGID, PPT, "loa3")).isFalse();
        assertThat(EidLevelOfAssurance.meetsMinimum(EidScheme.DIGID, MOBILE_2F, "loa3")).isFalse();
        assertThat(EidLevelOfAssurance.meetsMinimum(EidScheme.DIGID, SMARTCARD, "loa3")).isTrue();
        assertThat(EidLevelOfAssurance.meetsMinimum(EidScheme.DIGID, SMARTCARD_PKI, "loa3")).isTrue();
        // loa1 / loa2 / loa4
        assertThat(EidLevelOfAssurance.meetsMinimum(EidScheme.DIGID, PPT, "loa1")).isTrue();
        assertThat(EidLevelOfAssurance.meetsMinimum(EidScheme.DIGID, MOBILE_2F, "loa2")).isTrue();
        assertThat(EidLevelOfAssurance.meetsMinimum(EidScheme.DIGID, PPT, "loa2")).isFalse();
        assertThat(EidLevelOfAssurance.meetsMinimum(EidScheme.DIGID, SMARTCARD, "loa4")).isFalse();
        assertThat(EidLevelOfAssurance.meetsMinimum(EidScheme.DIGID, SMARTCARD_PKI, "loa4")).isTrue();
        // A classic class may also be configured as the minimum itself.
        assertThat(EidLevelOfAssurance.meetsMinimum(EidScheme.DIGID, "urn:nl-eid-gdi:1.0:LoA:High", SMARTCARD)).isTrue();
    }

    @Test
    void classicDigidClassesMeanNothingToEherkenningOrEidas() {
        for (final String cls : new String[] {PPT, MOBILE_2F, SMARTCARD, SMARTCARD_PKI}) {
            assertThat(EidLevelOfAssurance.rung(EidScheme.EHERKENNING, cls)).isZero();
            assertThat(EidLevelOfAssurance.rung(EidScheme.EIDAS, cls)).isZero();
            assertThat(EidLevelOfAssurance.meetsMinimum(EidScheme.EHERKENNING, cls, "loa2")).isFalse();
            assertThat(EidLevelOfAssurance.meetsMinimum(EidScheme.EIDAS, cls, "low")).isFalse();
            assertThat(EidLevelOfAssurance.isValidMinimum(EidScheme.EIDAS, cls)).isFalse();
        }
        assertThat(EidLevelOfAssurance.meetsMinimum(EidScheme.EHERKENNING,
                "urn:etoegang:core:assurance-class:loa3", "loa3")).isTrue();
        assertThat(EidLevelOfAssurance.meetsMinimum(EidScheme.EIDAS,
                "http://eidas.europa.eu/LoA/substantial", "substantial")).isTrue();
    }
}
