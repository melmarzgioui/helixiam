/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.security.mapper;

import io.helixiam.authorization.amqp.mapper.ProtocolMapperDto;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Helix IAM (Wave 3): resolving per-client protocol mappers into token claims at issuance.
 */
class ProtocolMapperResolverTest {

    private static ProtocolMapperDto attr(final String source, final String claim, final boolean access, final boolean id) {
        return new ProtocolMapperDto("m", "master", "c", "n", "USER_ATTRIBUTE", source, claim, access, id);
    }

    @Test
    void mapsAUserAttributeIntoTheClaim() {
        final Map<String, Object> out = ProtocolMapperResolver.claimsForTokenType(
                List.of(attr("department", "dept", true, true)),
                Map.of("department", "Tax", "email", "a@b.nl"), Set.of(), true);
        assertEquals("Tax", out.get("dept"));
    }

    @Test
    void hardcodedValueIsEmittedVerbatim() {
        final ProtocolMapperDto hard = new ProtocolMapperDto("m", "master", "c", "n", "HARDCODED", "gov-tier-1", "tier", true, true);
        assertEquals("gov-tier-1", ProtocolMapperResolver.claimsForTokenType(List.of(hard), Map.of(), Set.of(), true).get("tier"));
    }

    @Test
    void honoursTheAccessVsIdTokenFlags() {
        final List<ProtocolMapperDto> mappers = List.of(attr("email", "email_claim", true, false));
        assertTrue(ProtocolMapperResolver.claimsForTokenType(mappers, Map.of("email", "a@b.nl"), Set.of(), true).containsKey("email_claim"));
        assertFalse(ProtocolMapperResolver.claimsForTokenType(mappers, Map.of("email", "a@b.nl"), Set.of(), false).containsKey("email_claim"));
    }

    @Test
    void skipsAttributesMissingFromTheProfile() {
        final Map<String, Object> out = ProtocolMapperResolver.claimsForTokenType(
                List.of(attr("missing", "x", true, true)), Map.of("email", "a@b.nl"), Set.of(), true);
        assertFalse(out.containsKey("x"));
    }

    @Test
    void userRoleMapperEmitsTheRolesAsAListClaim() {
        final ProtocolMapperDto roleMapper = new ProtocolMapperDto("m", "master", "c", "n", "USER_ROLE", null, "my_roles", true, true);
        final Object value = ProtocolMapperResolver.claimsForTokenType(
                List.of(roleMapper), Map.of(), Set.of("admin", "viewer"), true).get("my_roles");
        assertTrue(value instanceof List);
        assertTrue(((List<?>) value).containsAll(List.of("admin", "viewer")));
    }

    @Test
    void userRoleMapperIsOmittedWhenTheUserHasNoRoles() {
        final ProtocolMapperDto roleMapper = new ProtocolMapperDto("m", "master", "c", "n", "USER_ROLE", null, "my_roles", true, true);
        assertFalse(ProtocolMapperResolver.claimsForTokenType(List.of(roleMapper), Map.of(), Set.of(), true).containsKey("my_roles"));
    }

    @Test
    void userRoleMapperHonoursTheIdTokenFlag() {
        final ProtocolMapperDto idOnly = new ProtocolMapperDto("m", "master", "c", "n", "USER_ROLE", null, "roles2", false, true);
        assertFalse(ProtocolMapperResolver.claimsForTokenType(List.of(idOnly), Map.of(), Set.of("admin"), true).containsKey("roles2"));
        assertTrue(ProtocolMapperResolver.claimsForTokenType(List.of(idOnly), Map.of(), Set.of("admin"), false).containsKey("roles2"));
    }

    // ---- 1.0 security (item 1) --------------------------------------------------------------------------

    @Test
    void userAttributeMapper_emitsTheConfiguredClaimName_notTheValue() {
        final var m = new ProtocolMapperDto("m", "master", "c", "n", "USER_ATTRIBUTE", "firm", "firm_id", true, true);
        final var claims = ProtocolMapperResolver.claimsForTokenType(java.util.List.of(m),
                java.util.Map.of("firm", "c-joes-plumbing"), java.util.Set.of(), true);
        org.assertj.core.api.Assertions.assertThat(claims).containsExactlyEntriesOf(java.util.Map.of("firm_id", "c-joes-plumbing"));
    }

    @Test
    void mappersNeverWriteReservedClaims_evenIfStoredBeforeValidationExisted() {
        final var sub = new ProtocolMapperDto("m1", "master", "c", "n1", "USER_ATTRIBUTE", "evil", "sub", true, true);
        final var aud = new ProtocolMapperDto("m2", "master", "c", "n2", "HARDCODED", "someone-else", "AUD", true, true);
        final var roles = new ProtocolMapperDto("m3", "master", "c", "n3", "USER_ROLE", null, "realm_access", true, true);
        final var claims = ProtocolMapperResolver.claimsForTokenType(java.util.List.of(sub, aud, roles),
                java.util.Map.of("evil", "joe-id"), java.util.Set.of("admin"), true);
        org.assertj.core.api.Assertions.assertThat(claims).isEmpty();
    }
}
