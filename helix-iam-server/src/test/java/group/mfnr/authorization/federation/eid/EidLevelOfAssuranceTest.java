package group.mfnr.authorization.federation.eid;

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
}
