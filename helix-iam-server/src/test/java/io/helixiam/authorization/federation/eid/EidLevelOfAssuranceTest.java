/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.eid;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

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
        assertThat(EidLevelOfAssurance.rung(EidScheme.EIDAS, "http://eidas.europa.eu/LoA/low")).isEqualTo(10);
        assertThat(EidLevelOfAssurance.rung(EidScheme.EIDAS, "http://eidas.europa.eu/LoA/substantial")).isEqualTo(20);
        assertThat(EidLevelOfAssurance.rung(EidScheme.EIDAS, "http://eidas.europa.eu/LoA/high")).isEqualTo(30);
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
        assertThat(EidLevelOfAssurance.rung(EidScheme.DIGID, "urn:nl-eid-gdi:1.0:LoA:Low")).isEqualTo(10);         // Basis
        assertThat(EidLevelOfAssurance.rung(EidScheme.DIGID, "urn:nl-eid-gdi:1.0:LoA:Midden")).isEqualTo(20);      // Midden
        assertThat(EidLevelOfAssurance.rung(EidScheme.DIGID, "urn:nl-eid-gdi:1.0:LoA:Substantial")).isEqualTo(30); // Substantieel
        assertThat(EidLevelOfAssurance.rung(EidScheme.DIGID, "urn:nl-eid-gdi:1.0:LoA:High")).isEqualTo(40);        // Hoog
    }

    @Test
    void digidSubstantieelDoesNotMeetAHoogMinimum() {
        assertThat(EidLevelOfAssurance.meetsMinimum(EidScheme.DIGID,
                "urn:nl-eid-gdi:1.0:LoA:Substantial", "urn:nl-eid-gdi:1.0:LoA:High")).isFalse();
    }

    // --- eHerkenning -------------------------------------------------------------------------------

    @Test
    void eherkenningUrnsMapToTheirRung() {
        assertThat(EidLevelOfAssurance.rung(EidScheme.EHERKENNING, "urn:etoegang:core:assurance-class:loa2")).isEqualTo(20);
        assertThat(EidLevelOfAssurance.rung(EidScheme.EHERKENNING, "urn:etoegang:core:assurance-class:loa3")).isEqualTo(30);
        assertThat(EidLevelOfAssurance.rung(EidScheme.EHERKENNING, "urn:etoegang:core:assurance-class:loa4")).isEqualTo(40);
        assertThat(EidLevelOfAssurance.meetsMinimum(EidScheme.EHERKENNING,
                "urn:etoegang:core:assurance-class:loa3", "urn:etoegang:core:assurance-class:loa3")).isTrue();
    }

    // --- EUDI Wallet (delegates to the eIDAS ladder; Task 3 / maintainer decision 2) ----------------

    @Test
    void eudiWalletDelegatesToTheEidasLadder() {
        for (final String uri : new String[] {"http://eidas.europa.eu/LoA/low", "http://eidas.europa.eu/LoA/substantial",
                "http://eidas.europa.eu/LoA/high"}) {
            assertThat(EidLevelOfAssurance.rung(EidScheme.EUDI_WALLET, uri))
                    .as("rung(EUDI_WALLET, %s) == rung(EIDAS, %s)", uri, uri)
                    .isEqualTo(EidLevelOfAssurance.rung(EidScheme.EIDAS, uri));
        }
        // the top of the eIDAS ladder (rung values are the ladder's own; the security branch spaced them out)
        assertThat(EidLevelOfAssurance.rung(EidScheme.EUDI_WALLET, "http://eidas.europa.eu/LoA/high"))
                .isGreaterThan(EidLevelOfAssurance.rung(EidScheme.EIDAS, "http://eidas.europa.eu/LoA/substantial"))
                .isGreaterThan(0);
    }

    @Test
    void eudiWalletHighMeetsASubstantialMinimum() {
        assertThat(EidLevelOfAssurance.meetsMinimum(EidScheme.EUDI_WALLET,
                "http://eidas.europa.eu/LoA/high", "http://eidas.europa.eu/LoA/substantial")).isTrue();
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
                .isEqualTo("urn:oasis:names:tc:SAML:2.0:ac:classes:Smartcard");
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
        assertThat(EidLevelOfAssurance.rung(EidScheme.DIGID, PPT)).isEqualTo(10);           // Basis
        assertThat(EidLevelOfAssurance.rung(EidScheme.DIGID, MOBILE_2F)).isEqualTo(20);     // Midden
        assertThat(EidLevelOfAssurance.rung(EidScheme.DIGID, SMARTCARD)).isEqualTo(30);     // Substantieel
        assertThat(EidLevelOfAssurance.rung(EidScheme.DIGID, SMARTCARD_PKI)).isEqualTo(40); // Hoog
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

    /**
     * Logius, Koppelvlakspecificatie DigiD SAML Authenticatie v3.5: Basis = PasswordProtectedTransport,
     * Midden = MobileTwoFactorContract, Substantieel = Smartcard, Hoog = SmartcardPKI. Every DigiD console keyword
     * (loa1..loa4 and the Dutch level names) resolves to that oasis class, so it is what the AuthnRequest asks for.
     */
    @ParameterizedTest(name = "DigiD {0} -> {1}")
    @CsvSource({
            "loa1, urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport",
            "basis, urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport",
            "loa2, urn:oasis:names:tc:SAML:2.0:ac:classes:MobileTwoFactorContract",
            "midden, urn:oasis:names:tc:SAML:2.0:ac:classes:MobileTwoFactorContract",
            "loa3, urn:oasis:names:tc:SAML:2.0:ac:classes:Smartcard",
            "Substantieel, urn:oasis:names:tc:SAML:2.0:ac:classes:Smartcard",
            "loa4, urn:oasis:names:tc:SAML:2.0:ac:classes:SmartcardPKI",
            "HOOG, urn:oasis:names:tc:SAML:2.0:ac:classes:SmartcardPKI"})
    void everyDigidKeyword_resolvesToTheLogiusOasisClass(final String keyword, final String oasisClass) {
        assertThat(EidLevelOfAssurance.canonicalMinimum(EidScheme.DIGID, keyword)).isEqualTo(oasisClass);
        assertThat(EidLevelOfAssurance.isValidMinimum(EidScheme.DIGID, keyword)).isTrue();
    }

    /** Per level: the class at that level meets the keyword's minimum, the class one level below does not. */
    @ParameterizedTest(name = "DigiD minimum {0}: {1} meets, {2} does not")
    @CsvSource({
            "basis, urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport, ''",
            "midden, urn:oasis:names:tc:SAML:2.0:ac:classes:MobileTwoFactorContract, urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport",
            "substantieel, urn:oasis:names:tc:SAML:2.0:ac:classes:Smartcard, urn:oasis:names:tc:SAML:2.0:ac:classes:MobileTwoFactorContract",
            "hoog, urn:oasis:names:tc:SAML:2.0:ac:classes:SmartcardPKI, urn:oasis:names:tc:SAML:2.0:ac:classes:Smartcard"})
    void digidComparisonPerLevel(final String keyword, final String atLevel, final String below) {
        assertThat(EidLevelOfAssurance.meetsMinimum(EidScheme.DIGID, atLevel, keyword)).isTrue();
        assertThat(EidLevelOfAssurance.meetsMinimum(EidScheme.DIGID, below, keyword)).isFalse();
        // A broker that asserts the nl-eid-gdi URN of the same level is still accepted.
        assertThat(EidLevelOfAssurance.meetsMinimum(EidScheme.DIGID, "urn:nl-eid-gdi:1.0:LoA:High", keyword)).isTrue();
    }

    @Test
    void theNlEidGdiUrnsStayAcceptedAsAStoredMinimum() {
        assertThat(EidLevelOfAssurance.canonicalMinimum(EidScheme.DIGID, "urn:nl-eid-gdi:1.0:LoA:Substantial"))
                .isEqualTo("urn:nl-eid-gdi:1.0:LoA:Substantial");
        assertThat(EidLevelOfAssurance.meetsMinimum(EidScheme.DIGID,
                "urn:oasis:names:tc:SAML:2.0:ac:classes:Smartcard", "urn:nl-eid-gdi:1.0:LoA:Substantial")).isTrue();
    }

    @Test
    void theRequestedClass_isTheOasisClassForDigid_andTheCanonicalMinimumOtherwise() {
        assertThat(EidLevelOfAssurance.requestedClass(EidScheme.DIGID, "urn:nl-eid-gdi:1.0:LoA:High"))
                .isEqualTo("urn:oasis:names:tc:SAML:2.0:ac:classes:SmartcardPKI");
        assertThat(EidLevelOfAssurance.requestedClass(EidScheme.DIGID, "midden"))
                .isEqualTo("urn:oasis:names:tc:SAML:2.0:ac:classes:MobileTwoFactorContract");
        assertThat(EidLevelOfAssurance.requestedClass(EidScheme.EIDAS, "substantial"))
                .isEqualTo("http://eidas.europa.eu/LoA/substantial");
        assertThat(EidLevelOfAssurance.requestedClass(EidScheme.EHERKENNING, "loa2plus"))
                .isEqualTo("urn:etoegang:core:assurance-class:loa2plus");
        assertThat(EidLevelOfAssurance.requestedClass(EidScheme.DIGID, "loa9")).isNull();
        // the comparison is unchanged: a stored nl-eid-gdi minimum still ranks either form of the level
        assertThat(EidLevelOfAssurance.meetsMinimum(EidScheme.DIGID, "urn:nl-eid-gdi:1.0:LoA:Substantial",
                "urn:nl-eid-gdi:1.0:LoA:Substantial")).isTrue();
    }

    @Test
    void theDutchLevelNamesAreDigidOnly() {
        assertThat(EidLevelOfAssurance.canonicalMinimum(EidScheme.EHERKENNING, "substantieel")).isNull();
        assertThat(EidLevelOfAssurance.canonicalMinimum(EidScheme.EIDAS, "hoog")).isNull();
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

    // --- eHerkenning EH2+ sits between EH2 and EH3 --------------------------------------------------

    private static final String EH2 = "urn:etoegang:core:assurance-class:loa2";
    private static final String EH2_PLUS = "urn:etoegang:core:assurance-class:loa2plus";
    private static final String EH3 = "urn:etoegang:core:assurance-class:loa3";

    @Test
    void eherkenningLoa2plus_isItsOwnRung_betweenLoa2AndLoa3() {
        assertThat(EidLevelOfAssurance.rung(EidScheme.EHERKENNING, EH2_PLUS))
                .isGreaterThan(EidLevelOfAssurance.rung(EidScheme.EHERKENNING, EH2))
                .isLessThan(EidLevelOfAssurance.rung(EidScheme.EHERKENNING, EH3));
    }

    @Test
    void aLoa2Assertion_doesNotMeetALoa2plusMinimum() {
        assertThat(EidLevelOfAssurance.meetsMinimum(EidScheme.EHERKENNING, EH2, "loa2plus")).isFalse();
        assertThat(EidLevelOfAssurance.meetsMinimum(EidScheme.EHERKENNING, EH2, EH2_PLUS)).isFalse();
        assertThat(EidLevelOfAssurance.meetsMinimum(EidScheme.EHERKENNING, EH2_PLUS, "loa2plus")).isTrue();
        assertThat(EidLevelOfAssurance.meetsMinimum(EidScheme.EHERKENNING, EH2_PLUS, "loa2")).isTrue();
        assertThat(EidLevelOfAssurance.meetsMinimum(EidScheme.EHERKENNING, EH3, "loa2plus")).isTrue();
        assertThat(EidLevelOfAssurance.meetsMinimum(EidScheme.EHERKENNING, EH2_PLUS, "loa3")).isFalse();
    }

    // --- merge of the wallet and security branches (final review M1): the wallet tag uses the eIDAS ladder -----

    private static final String EIDAS_HIGH = "http://eidas.europa.eu/LoA/high";
    private static final String EIDAS_SUBSTANTIAL = "http://eidas.europa.eu/LoA/substantial";

    @Test
    void theWalletTag_resolvesItsMinimumOnTheEidasLadder_likeItsRung() {
        assertThat(EidLevelOfAssurance.canonicalMinimum(EidScheme.EUDI_WALLET, EIDAS_HIGH)).isEqualTo(EIDAS_HIGH);
        assertThat(EidLevelOfAssurance.canonicalMinimum(EidScheme.EUDI_WALLET, "high")).isEqualTo(EIDAS_HIGH);
        assertThat(EidLevelOfAssurance.isValidMinimum(EidScheme.EUDI_WALLET, "substantial")).isTrue();
        assertThat(EidLevelOfAssurance.isValidMinimum(EidScheme.EUDI_WALLET, "loa9")).isFalse();
    }

    @Test
    void aWalletLogin_atTheDefaultMinimumHigh_isAccepted_andAnUnknownMinimumIsStillNeverMet() {
        assertThat(EidLevelOfAssurance.meetsMinimum(EidScheme.EUDI_WALLET, EIDAS_HIGH, EIDAS_HIGH)).isTrue();
        assertThat(EidLevelOfAssurance.meetsMinimum(EidScheme.EUDI_WALLET, EIDAS_HIGH, "high")).isTrue();
        assertThat(EidLevelOfAssurance.meetsMinimum(EidScheme.EUDI_WALLET, EIDAS_SUBSTANTIAL, EIDAS_HIGH)).isFalse();
        assertThat(EidLevelOfAssurance.meetsMinimum(EidScheme.EUDI_WALLET, EIDAS_HIGH, "loa9")).isFalse();
    }

    @Test
    void walletProtocols_areNotEidProtocols() {
        for (final String protocol : java.util.List.of("eudi-wallet", "openid4vp", "wallet", "EUDI-WALLET")) {
            assertThat(EidScheme.isEidProtocol(protocol)).as(protocol).isFalse();
        }
        assertThat(EidScheme.isEidProtocol("eidas")).isTrue();
    }
}
