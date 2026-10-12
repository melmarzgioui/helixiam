/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.wallet.dcql;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * {@link DcqlQueryBuilder}: the PID preset is the golden query of docs/eudi-wallet-spec-notes.md §1.4 (field names
 * per OpenID4VP §6 and Appendix B), claims mapped per the PID Rulebook table (notes §7.2).
 */
class DcqlQueryBuilderTest {

    private static final ObjectMapper JSON = new ObjectMapper();
    private static final String SD_JWT = "dc+sd-jwt";
    private static final String MDOC = "mso_mdoc";
    private static final PidQuerySpec PRESET = new PidQuerySpec(List.of("urn:eudi:pid:1"),
            PidQuerySpec.DEFAULT_MDOC_DOCTYPE, List.of("given_name", "family_name", "birthdate"));

    private static final String SD_JWT_QUERY = """
            { "id": "pid_sd_jwt", "format": "dc+sd-jwt",
              "meta": { "vct_values": ["urn:eudi:pid:1"] },
              "claims": [ {"path": ["given_name"]}, {"path": ["family_name"]}, {"path": ["birthdate"]} ] }""";
    private static final String MDOC_QUERY = """
            { "id": "pid_mdoc", "format": "mso_mdoc",
              "meta": { "doctype_value": "eu.europa.ec.eudi.pid.1" },
              "claims": [ {"path": ["eu.europa.ec.eudi.pid.1", "given_name"]},
                          {"path": ["eu.europa.ec.eudi.pid.1", "family_name"]},
                          {"path": ["eu.europa.ec.eudi.pid.1", "birth_date"]} ] }""";

    private static JsonNode json(final String text) throws Exception {
        return JSON.readTree(text);
    }

    private static ObjectNode build(final PidQuerySpec spec, final List<String> formats) {
        return new DcqlQueryBuilder().pidQuery(spec, formats);
    }

    @Test
    void bothFormatsGiveTheNotesPresetExactly() throws Exception {
        assertThat((JsonNode) build(PRESET, List.of(SD_JWT, MDOC))).isEqualTo(json("""
                { "credentials": [ %s, %s ],
                  "credential_sets": [ { "options": [ ["pid_sd_jwt"], ["pid_mdoc"] ] } ] }"""
                .formatted(SD_JWT_QUERY, MDOC_QUERY)));
    }

    @Test
    void credentialOrderFollowsTheFormatOrder() throws Exception {
        assertThat((JsonNode) build(PRESET, List.of(MDOC, SD_JWT))).isEqualTo(json("""
                { "credentials": [ %s, %s ],
                  "credential_sets": [ { "options": [ ["pid_mdoc"], ["pid_sd_jwt"] ] } ] }"""
                .formatted(MDOC_QUERY, SD_JWT_QUERY)));
    }

    @Test
    void sdJwtOnlyIsOneRequiredQueryWithoutCredentialSets() throws Exception {
        assertThat((JsonNode) build(PRESET, List.of(SD_JWT)))
                .isEqualTo(json("{ \"credentials\": [ %s ] }".formatted(SD_JWT_QUERY)));
    }

    @Test
    void mdocOnlyIsOneRequiredQueryWithoutCredentialSets() throws Exception {
        assertThat((JsonNode) build(PRESET, List.of(MDOC)))
                .isEqualTo(json("{ \"credentials\": [ %s ] }".formatted(MDOC_QUERY)));
    }

    @Test
    void everyConfiguredVctIsListedIncludingNationalPids() {
        final PidQuerySpec spec = new PidQuerySpec(List.of("urn:eudi:pid:1", "urn:eudi:pid:de:1"),
                PidQuerySpec.DEFAULT_MDOC_DOCTYPE, List.of("given_name"));

        assertThat(build(spec, List.of(SD_JWT)).at("/credentials/0/meta/vct_values").toString())
                .isEqualTo("[\"urn:eudi:pid:1\",\"urn:eudi:pid:de:1\"]");
    }

    @Test
    void theMdocDoctypeIsUsedAsGivenWhileThePidNamespaceStays() {
        final PidQuerySpec spec = new PidQuerySpec(List.of("urn:eudi:pid:1"), "eu.europa.ec.eudi.pid.de.1",
                List.of("given_name"));

        final ObjectNode query = build(spec, List.of(MDOC));

        assertThat(query.at("/credentials/0/meta/doctype_value").asText()).isEqualTo("eu.europa.ec.eudi.pid.de.1");
        assertThat(query.at("/credentials/0/claims/0/path").toString())
                .isEqualTo("[\"eu.europa.ec.eudi.pid.1\",\"given_name\"]");
    }

    @Test
    void nestedAndRenamedClaimsMapToEachFormatsPath() throws Exception {
        final PidQuerySpec spec = new PidQuerySpec(List.of("urn:eudi:pid:1"), PidQuerySpec.DEFAULT_MDOC_DOCTYPE,
                List.of("nationalities", "place_of_birth", "address.street_address", "address.locality",
                        "personal_administrative_number", "picture", "email"));

        final ObjectNode query = build(spec, List.of(SD_JWT, MDOC));

        assertThat(query.at("/credentials/0/claims")).isEqualTo(json("""
                [ {"path": ["nationalities"]}, {"path": ["place_of_birth"]}, {"path": ["address", "street_address"]},
                  {"path": ["address", "locality"]}, {"path": ["personal_administrative_number"]},
                  {"path": ["picture"]}, {"path": ["email"]} ]"""));
        assertThat(query.at("/credentials/1/claims")).isEqualTo(json("""
                [ {"path": ["eu.europa.ec.eudi.pid.1", "nationality"]},
                  {"path": ["eu.europa.ec.eudi.pid.1", "place_of_birth"]},
                  {"path": ["eu.europa.ec.eudi.pid.1", "resident_street"]},
                  {"path": ["eu.europa.ec.eudi.pid.1", "resident_city"]},
                  {"path": ["eu.europa.ec.eudi.pid.1", "personal_administrative_number"]},
                  {"path": ["eu.europa.ec.eudi.pid.1", "portrait"]},
                  {"path": ["eu.europa.ec.eudi.pid.1", "email_address"]} ]"""));
    }

    @Test
    void aClaimWithoutAnMdocElementIsOnlyRequestedFromSdJwt() {
        final PidQuerySpec spec = new PidQuerySpec(List.of("urn:eudi:pid:1"), PidQuerySpec.DEFAULT_MDOC_DOCTYPE,
                List.of("given_name", "address.house_number"));

        final ObjectNode query = build(spec, List.of(SD_JWT, MDOC));

        assertThat(query.at("/credentials/0/claims")).hasSize(2);
        assertThat(query.at("/credentials/1/claims")).hasSize(1);
        assertThat(query.at("/credentials/1/claims/0/path/1").asText()).isEqualTo("given_name");
    }

    @Test
    void mdocWithOnlyClaimsItCannotCarryIsRefused() {
        final PidQuerySpec spec = new PidQuerySpec(List.of("urn:eudi:pid:1"), PidQuerySpec.DEFAULT_MDOC_DOCTYPE,
                List.of("address.house_number"));

        assertThatThrownBy(() -> build(spec, List.of(MDOC))).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void ageOver18IsNotAPidClaim() {
        final PidQuerySpec spec = new PidQuerySpec(List.of("urn:eudi:pid:1"), PidQuerySpec.DEFAULT_MDOC_DOCTYPE,
                List.of("given_name", "age_over_18"));

        assertThatThrownBy(() -> build(spec, List.of(SD_JWT))).isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("age_over_18");
    }

    @Test
    void unknownOrDuplicateClaimsAreRefused() {
        assertThatThrownBy(() -> build(new PidQuerySpec(List.of("urn:eudi:pid:1"), null, List.of("shoe_size")),
                List.of(SD_JWT))).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> build(new PidQuerySpec(List.of("urn:eudi:pid:1"), null,
                List.of("given_name", "given_name")), List.of(SD_JWT))).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> build(new PidQuerySpec(List.of("urn:eudi:pid:1"), null, List.of()),
                List.of(SD_JWT))).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void formatsMustBeKnownNonEmptyAndDistinct() {
        assertThatThrownBy(() -> build(PRESET, List.of())).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> build(PRESET, List.of("jwt_vc_json"))).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> build(PRESET, List.of(SD_JWT, SD_JWT)))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void aFormatNeedsItsTypeConfigured() {
        assertThatThrownBy(() -> build(new PidQuerySpec(List.of(), PidQuerySpec.DEFAULT_MDOC_DOCTYPE,
                List.of("given_name")), List.of(SD_JWT))).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> build(new PidQuerySpec(List.of("urn:eudi:pid:1"), " ", List.of("given_name")),
                List.of(MDOC))).isInstanceOf(IllegalArgumentException.class);
        // An unused type may be absent: SD-JWT only needs no doctype.
        assertThat(build(new PidQuerySpec(List.of("urn:eudi:pid:1"), null, List.of("given_name")), List.of(SD_JWT)))
                .isNotNull();
    }

    @Test
    void eachCallReturnsAFreshQuery() {
        final DcqlQueryBuilder builder = new DcqlQueryBuilder();
        final ObjectNode first = builder.pidQuery(PRESET, List.of(SD_JWT));
        first.removeAll();

        assertThat(builder.pidQuery(PRESET, List.of(SD_JWT)).has("credentials")).isTrue();
    }

    @Test
    void isPidClaim_knowsTheCanonicalNames_only() {
        assertThat(DcqlQueryBuilder.isPidClaim("birthdate")).isTrue();
        assertThat(DcqlQueryBuilder.isPidClaim("address.locality")).isTrue();
        assertThat(DcqlQueryBuilder.isPidClaim("address.house_number")).isTrue();
        assertThat(DcqlQueryBuilder.isPidClaim("birth_date")).isFalse(); // the mdoc name, not the canonical one
        assertThat(DcqlQueryBuilder.isPidClaim("age_over_18")).isFalse();
        assertThat(DcqlQueryBuilder.isPidClaim(null)).isFalse();
    }
}
