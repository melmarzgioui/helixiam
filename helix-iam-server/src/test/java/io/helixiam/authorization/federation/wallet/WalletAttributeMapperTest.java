/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.wallet;

import io.helixiam.authorization.federation.AttributeMapperRules;
import io.helixiam.authorization.federation.spi.BrokeredIdentity;
import io.helixiam.authorization.federation.wallet.dcql.MatchedPresentations;
import org.junit.jupiter.api.Test;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * {@link WalletAttributeMapper}: PID Rulebook attribute mapping and eIDAS level of assurance (ARF Annex 3.01 PID
 * Rulebook v1.7, 17 July 2026; docs/eudi-wallet-spec-notes.md §7.2).
 */
class WalletAttributeMapperTest {

    private static final String SD_JWT = "dc+sd-jwt";
    private static final String MDOC = "mso_mdoc";
    private static final String NS = "eu.europa.ec.eudi.pid.1";
    private static final String ISSUER_DN = "CN=PID Issuer";

    private static VerifiedPresentation presentation(final String format, final Map<String, Object> claims,
            final String issuerDn) {
        return new VerifiedPresentation(format, "irrelevant-for-mapping", claims, issuerDn, "1f", "VALID");
    }

    private static MatchedPresentations matched(final VerifiedPresentation... presentations) {
        return new MatchedPresentations(List.of(presentations), Set.of());
    }

    /** Overwrites one mdoc PID element in-place, for tests that make the mdoc side disagree with the SD-JWT side. */
    @SuppressWarnings("unchecked")
    private static void setMdocElement(final Map<String, Object> mdocClaims, final String element,
            final Object value) {
        ((Map<String, Object>) mdocClaims.get(NS)).put(element, value);
    }

    private static Map<String, Object> fullSdJwtPid() {
        final Map<String, Object> address = new LinkedHashMap<>();
        address.put("locality", "Berlin");
        address.put("country", "DE");
        address.put("house_number", "12");

        final Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("given_name", "Erika");
        claims.put("family_name", "Mustermann");
        claims.put("birthdate", "1964-08-12");
        claims.put("nationalities", List.of("DE"));
        claims.put("place_of_birth", "Berlin");
        claims.put("address", address);
        claims.put("issuing_country", "DE");
        claims.put("issuing_authority", "DE Government");
        return claims;
    }

    private static Map<String, Object> fullMdocPid() {
        final Map<String, Object> elements = new LinkedHashMap<>();
        elements.put("given_name", "Erika");
        elements.put("family_name", "Mustermann");
        elements.put("birth_date", "1964-08-12");
        elements.put("nationality", List.of("DE"));
        elements.put("place_of_birth", "Berlin");
        elements.put("resident_city", "Berlin");
        elements.put("resident_country", "DE");
        elements.put("issuing_country", "DE");
        elements.put("issuing_authority", "DE Government");
        return Map.of(NS, elements);
    }

    // ------------------------------------------------------------------------------------------- same attributes

    @Test
    void sdJwtAndMdocPidsMapToIdenticalAttributes() {
        final BrokeredIdentity fromSdJwt = WalletAttributeMapper.map("eudi-wallet", "sub-1",
                matched(presentation(SD_JWT, fullSdJwtPid(), ISSUER_DN)), null);
        final BrokeredIdentity fromMdoc = WalletAttributeMapper.map("eudi-wallet", "sub-1",
                matched(presentation(MDOC, fullMdocPid(), ISSUER_DN)), null);

        // helix_wallet_format differs by design (it names which format was presented); address.house_number has no
        // mdoc element (SD-JWT VC only, see the class javadoc) so it is naturally absent from the mdoc side.
        // Everything else must match.
        final Map<String, String> sdJwtAttrs = new LinkedHashMap<>(fromSdJwt.attributes());
        final Map<String, String> mdocAttrs = new LinkedHashMap<>(fromMdoc.attributes());
        sdJwtAttrs.remove("helix_wallet_format");
        mdocAttrs.remove("helix_wallet_format");
        sdJwtAttrs.remove("address.house_number");
        assertThat(sdJwtAttrs).isEqualTo(mdocAttrs);
        assertThat(sdJwtAttrs).containsEntry("given_name", "Erika").containsEntry("family_name", "Mustermann")
                .containsEntry("birthdate", "1964-08-12").containsEntry("nationalities", "DE")
                .containsEntry("place_of_birth", "Berlin").containsEntry("address.locality", "Berlin")
                .containsEntry("address.country", "DE").containsEntry("issuing_country", "DE")
                .containsEntry("issuing_authority", "DE Government");
    }

    @Test
    void sdJwtOnlyAlsoMapsAddressHouseNumber_noMdocElementExists() {
        final BrokeredIdentity identity = WalletAttributeMapper.map("eudi-wallet", "sub-1",
                matched(presentation(SD_JWT, fullSdJwtPid(), ISSUER_DN)), null);

        assertThat(identity.attributes()).containsEntry("address.house_number", "12");
    }

    @Test
    void mdocHasNoAddressHouseNumberElement_neverMapped() {
        final BrokeredIdentity identity = WalletAttributeMapper.map("eudi-wallet", "sub-1",
                matched(presentation(MDOC, fullMdocPid(), ISSUER_DN)), null);

        assertThat(identity.attributes()).doesNotContainKey("address.house_number");
    }

    @Test
    void nationalitiesIsAlwaysAListEvenWithSeveralEntries() {
        final Map<String, Object> claims = fullSdJwtPid();
        claims.put("nationalities", List.of("DE", "NL"));

        final BrokeredIdentity identity = WalletAttributeMapper.map("eudi-wallet", "sub-1",
                matched(presentation(SD_JWT, claims, ISSUER_DN)), null);

        assertThat(identity.attributes()).containsEntry("nationalities", "DE,NL");
    }

    // ------------------------------------------------------------------------------------------- not mapped

    @Test
    void ageOver18IsDroppedEvenIfPresent() {
        final Map<String, Object> claims = fullSdJwtPid();
        claims.put("age_over_18", true);

        final BrokeredIdentity identity = WalletAttributeMapper.map("eudi-wallet", "sub-1",
                matched(presentation(SD_JWT, claims, ISSUER_DN)), null);

        assertThat(identity.attributes()).doesNotContainKey("age_over_18");
    }

    @Test
    void unknownExtraClaimsAreNotMapped() {
        final Map<String, Object> claims = fullSdJwtPid();
        claims.put("sex", "F");
        claims.put("personal_administrative_number", "ADMIN-1");
        claims.put("picture", "base64...");

        final BrokeredIdentity identity = WalletAttributeMapper.map("eudi-wallet", "sub-1",
                matched(presentation(SD_JWT, claims, ISSUER_DN)), null);

        assertThat(identity.attributes()).doesNotContainKeys("sex", "personal_administrative_number", "picture");
    }

    // ------------------------------------------------------------------------------------------- dates

    @Test
    void birthdateIsNormalisedToIsoForm() {
        final Map<String, Object> claims = fullSdJwtPid();
        claims.put("birthdate", " 1964-08-12 ");

        final BrokeredIdentity identity = WalletAttributeMapper.map("eudi-wallet", "sub-1",
                matched(presentation(SD_JWT, claims, ISSUER_DN)), null);

        assertThat(identity.attributes()).containsEntry("birthdate", "1964-08-12");
    }

    @Test
    void aMalformedBirthdateIsRefused() {
        final Map<String, Object> claims = fullSdJwtPid();
        claims.put("birthdate", "12 August 1964");

        assertThatThrownBy(() -> WalletAttributeMapper.map("eudi-wallet", "sub-1",
                matched(presentation(SD_JWT, claims, ISSUER_DN)), null))
                .isInstanceOf(WalletVerificationException.class)
                .satisfies(e -> assertThat(((WalletVerificationException) e).code())
                        .isEqualTo(WalletErrorCode.INVALID_RESPONSE));
    }

    // ------------------------------------------------------------------------------------------- both formats

    @Test
    void bothFormatsAgreeing_sdJwtIsAuthoritativeForOtherAttributes() {
        final Map<String, Object> mdocClaims = fullMdocPid();
        // mdoc disagrees on something SD-JWT is authoritative for; this must NOT surface.
        setMdocElement(mdocClaims, "issuing_authority", "A different authority entirely");

        final BrokeredIdentity identity = WalletAttributeMapper.map("eudi-wallet", "sub-1",
                matched(presentation(SD_JWT, fullSdJwtPid(), ISSUER_DN), presentation(MDOC, mdocClaims, "CN=Other Issuer")),
                null);

        assertThat(identity.attributes()).containsEntry("helix_wallet_format", "both")
                .containsEntry("helix_wallet_issuer", ISSUER_DN) // the SD-JWT's issuer, not the mdoc's
                .containsEntry("issuing_authority", "DE Government"); // SD-JWT's value, not mdoc's
    }

    @Test
    void bothFormatsDisagreeingOnGivenName_refused() {
        final Map<String, Object> mdocClaims = fullMdocPid();
        setMdocElement(mdocClaims, "given_name", "Someone Else");

        assertThatThrownBy(() -> WalletAttributeMapper.map("eudi-wallet", "sub-1",
                matched(presentation(SD_JWT, fullSdJwtPid(), ISSUER_DN), presentation(MDOC, mdocClaims, ISSUER_DN)),
                null))
                .isInstanceOf(WalletVerificationException.class)
                .satisfies(e -> assertThat(((WalletVerificationException) e).code())
                        .isEqualTo(WalletErrorCode.INVALID_RESPONSE));
    }

    @Test
    void bothFormatsDisagreeingOnBirthdate_refused() {
        final Map<String, Object> mdocClaims = fullMdocPid();
        setMdocElement(mdocClaims, "birth_date", "1990-01-01");

        assertThatThrownBy(() -> WalletAttributeMapper.map("eudi-wallet", "sub-1",
                matched(presentation(SD_JWT, fullSdJwtPid(), ISSUER_DN), presentation(MDOC, mdocClaims, ISSUER_DN)),
                null))
                .isInstanceOf(WalletVerificationException.class);
    }

    @Test
    void agreementIsCheckedAfterTrimAndUnicodeNfc_butNamesAreNeverCaseFolded() {
        // "Mustermann" with a combining accent (NFD) on the mdoc side must still agree with the SD-JWT's precomposed
        // form after NFC-normalising both; a differently-CASED name must still be refused (names are never
        // case-folded).
        final Map<String, Object> sdJwtClaims = fullSdJwtPid();
        sdJwtClaims.put("given_name", "José"); // NFC precomposed é

        final Map<String, Object> mdocClaims = fullMdocPid();
        setMdocElement(mdocClaims, "given_name", "José"); // NFD: e + combining acute

        final BrokeredIdentity identity = WalletAttributeMapper.map("eudi-wallet", "sub-1",
                matched(presentation(SD_JWT, sdJwtClaims, ISSUER_DN), presentation(MDOC, mdocClaims, ISSUER_DN)),
                null);

        assertThat(identity.attributes()).containsEntry("given_name", "José");
    }

    @Test
    void caseDifferenceInNameIsStillARefusedDisagreement() {
        final Map<String, Object> mdocClaims = fullMdocPid();
        setMdocElement(mdocClaims, "family_name", "MUSTERMANN");

        assertThatThrownBy(() -> WalletAttributeMapper.map("eudi-wallet", "sub-1",
                matched(presentation(SD_JWT, fullSdJwtPid(), ISSUER_DN), presentation(MDOC, mdocClaims, ISSUER_DN)),
                null))
                .isInstanceOf(WalletVerificationException.class);
    }

    // ------------------------------------------------------------------------------------------- helix attributes

    @Test
    void helixWalletFormatIsSdJwtWhenOnlySdJwtPresented() {
        final BrokeredIdentity identity = WalletAttributeMapper.map("eudi-wallet", "sub-1",
                matched(presentation(SD_JWT, fullSdJwtPid(), ISSUER_DN)), null);

        assertThat(identity.attributes()).containsEntry("helix_wallet_format", "dc+sd-jwt")
                .containsEntry("helix_wallet_issuer", ISSUER_DN);
    }

    @Test
    void helixWalletFormatIsMdocWhenOnlyMdocPresented() {
        final BrokeredIdentity identity = WalletAttributeMapper.map("eudi-wallet", "sub-1",
                matched(presentation(MDOC, fullMdocPid(), ISSUER_DN)), null);

        assertThat(identity.attributes()).containsEntry("helix_wallet_format", "mso_mdoc")
                .containsEntry("helix_wallet_issuer", ISSUER_DN);
    }

    @Test
    void emailIsAlwaysNullAndUnverified() {
        final BrokeredIdentity identity = WalletAttributeMapper.map("eudi-wallet", "sub-1",
                matched(presentation(SD_JWT, fullSdJwtPid(), ISSUER_DN)), null);

        assertThat(identity.email()).isNull();
        assertThat(identity.emailVerified()).isFalse();
    }

    @Test
    void idpAliasAndExternalSubjectArePassedThroughUnchanged() {
        final BrokeredIdentity identity = WalletAttributeMapper.map("my-wallet", "DE/PAN-0001",
                matched(presentation(SD_JWT, fullSdJwtPid(), ISSUER_DN)), null);

        assertThat(identity.idpAlias()).isEqualTo("my-wallet");
        assertThat(identity.externalSubject()).isEqualTo("DE/PAN-0001");
    }

    // ------------------------------------------------------------------------------------------- level of assurance

    @Test
    void loaIsAlwaysEidasHighWhenVerified() {
        final BrokeredIdentity identity = WalletAttributeMapper.map("eudi-wallet", "sub-1",
                matched(presentation(SD_JWT, fullSdJwtPid(), ISSUER_DN)), null);

        assertThat(identity.levelOfAssurance()).isEqualTo("http://eidas.europa.eu/LoA/high");
    }

    @Test
    void blankMinimumLoaIsAlwaysMet() {
        assertThat(WalletAttributeMapper.map("eudi-wallet", "sub-1",
                matched(presentation(SD_JWT, fullSdJwtPid(), ISSUER_DN)), null).levelOfAssurance())
                .isEqualTo("http://eidas.europa.eu/LoA/high");
    }

    @Test
    void aRealEidasMinimumUpToHighIsAlwaysMet() {
        assertThat(WalletAttributeMapper.map("eudi-wallet", "sub-1",
                matched(presentation(SD_JWT, fullSdJwtPid(), ISSUER_DN)), "http://eidas.europa.eu/LoA/substantial")
                .levelOfAssurance()).isEqualTo("http://eidas.europa.eu/LoA/high");
    }

    @Test
    void aMinimumLoaTheLadderDoesNotRecogniseIsImpossibleToSatisfy_refused() {
        // Fabricated: no real config can express this (WalletConfigValidator restricts minimumLoa to a recognised
        // eIDAS rung), but EidLevelOfAssurance#meetsMinimum alone would wrongly treat an unrecognised non-blank
        // minimum as "always met" (rung 0, same as blank) — this proves the mapper does not trust that loophole.
        assertThatThrownBy(() -> WalletAttributeMapper.map("eudi-wallet", "sub-1",
                matched(presentation(SD_JWT, fullSdJwtPid(), ISSUER_DN)), "http://eidas.europa.eu/LoA/very-high"))
                .isInstanceOf(WalletVerificationException.class)
                .satisfies(e -> assertThat(((WalletVerificationException) e).code())
                        .isEqualTo(WalletErrorCode.INVALID_RESPONSE));
    }

    // ------------------------------------------------------------------------------------------- admin mapper rules

    @Test
    void anAdminMapperRuleRenamesAClaim_appliedAfterTheDefaultMapping() {
        // Task 20 only produces the default mapping; the admin's per-IdP "mappers" CSV (AttributeMapperRules) is the
        // SAME mechanism eid/OIDC/SAML providers use, applied by the broker AFTER this mapping — no parallel
        // mechanism here.
        final BrokeredIdentity identity = WalletAttributeMapper.map("eudi-wallet", "sub-1",
                matched(presentation(SD_JWT, fullSdJwtPid(), ISSUER_DN)), null);

        final Map<String, String> renamed = AttributeMapperRules.apply(identity, "given_name=firstName");

        assertThat(renamed).containsEntry("firstName", "Erika");
    }

    // ------------------------------------------------------------------------------------------- failure

    @Test
    void noPresentationsAtAll_refused() {
        assertThatThrownBy(() -> WalletAttributeMapper.map("eudi-wallet", "sub-1", matched(), null))
                .isInstanceOf(WalletVerificationException.class)
                .satisfies(e -> assertThat(((WalletVerificationException) e).code())
                        .isEqualTo(WalletErrorCode.INVALID_RESPONSE));
    }
}
