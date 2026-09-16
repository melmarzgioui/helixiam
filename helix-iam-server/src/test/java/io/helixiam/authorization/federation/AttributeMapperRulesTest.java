/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation;

import io.helixiam.authorization.federation.spi.BrokeredIdentity;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Helix IAM B5: per-IdP attribute/claim mappers. {@link AttributeMapperRules} parses the admin-configured
 * {@code mappers} CSV ("source=target,…") and projects an upstream identity's claims onto local user
 * attributes — the runtime engine behind the console's mapper editor. Pure + fully unit-testable.
 */
class AttributeMapperRulesTest {

    private BrokeredIdentity identity() {
        final Map<String, String> attrs = new HashMap<>();
        attrs.put("given_name", "Ada");
        attrs.put("department", "R&D");
        attrs.put("groups", "eng,leads");
        attrs.put("blank", "  ");
        return new BrokeredIdentity("acme", "sub-1", "ada@x.io", true, attrs);
    }

    @Test
    void parsesSourceTargetPairsPreservingOrderAndSkippingMalformedEntries() {
        // Genuinely malformed entries (empty source / empty target / blank) are dropped; a bare token is a
        // self-map and is covered separately.
        final Map<String, String> rules = AttributeMapperRules.parse("dept=department, groups=groups ,, =x, y=");

        assertThat(rules).containsExactly(
                Map.entry("dept", "department"),
                Map.entry("groups", "groups"));
    }

    @Test
    void treatsABareAttributeAsASelfMap_matchingTheConsoleRoundTrip() {
        // The console serialises a source==target mapper as the bare attribute ("NameID", not "NameID=NameID").
        final Map<String, String> rules = AttributeMapperRules.parse("department, email=contact");

        assertThat(rules).containsExactly(
                Map.entry("department", "department"),
                Map.entry("email", "contact"));
    }

    @Test
    void appliesABareSelfMapAttributeOntoTheSameLocalName() {
        final Map<String, String> mapped = AttributeMapperRules.apply(identity(), "department");

        assertThat(mapped).containsEntry("department", "R&D");
    }

    @Test
    void parseReturnsEmptyForNullOrBlank() {
        assertThat(AttributeMapperRules.parse(null)).isEmpty();
        assertThat(AttributeMapperRules.parse("   ")).isEmpty();
        assertThat(AttributeMapperRules.parse(",, ,")).isEmpty();
    }

    @Test
    void appliesRulesProjectingUpstreamClaimsOntoLocalAttributeNames() {
        final Map<String, String> mapped = AttributeMapperRules.apply(identity(), "department=dept,groups=teams");

        assertThat(mapped).containsEntry("dept", "R&D").containsEntry("teams", "eng,leads");
    }

    @Test
    void resolvesTheEmailAndSubjectSynonymsFromTheIdentityFields() {
        // 'email' / 'sub' are not in the raw attribute map but must resolve to the identity's fields.
        final Map<String, String> mapped = AttributeMapperRules.apply(identity(), "email=contact,sub=externalId");

        assertThat(mapped).containsEntry("contact", "ada@x.io").containsEntry("externalId", "sub-1");
    }

    @Test
    void skipsRulesWhoseSourceClaimIsAbsentOrBlank() {
        final Map<String, String> mapped = AttributeMapperRules.apply(identity(), "missing=x,blank=y,given_name=firstName");

        assertThat(mapped).containsOnlyKeys("firstName");
        assertThat(mapped).containsEntry("firstName", "Ada");
    }

    @Test
    void emptyMapperConfigProducesNoExtraAttributes() {
        assertThat(AttributeMapperRules.apply(identity(), null)).isEmpty();
        assertThat(AttributeMapperRules.apply(identity(), "")).isEmpty();
    }
}
