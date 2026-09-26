/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.LinkedHashMap;
import java.util.Map;

import io.helixiam.authorization.amqp.user.UserPublisher;

import org.junit.jupiter.api.Test;

/**
 * Claim-injection regression: the OIDC claim profile must map an attribute's NAME to a claim (never use the
 * attribute VALUE as the claim name), and must never let a user-controlled attribute set a reserved
 * identity/authority claim (sub, roles, aud, …). A prior bug used {@code getOrDefault(key, value)}, so an
 * unmapped attribute's value became a claim name — a user could forge claims.
 */
class UserInfoServiceTest {

    private static UserInfoService serviceWith(final Map<String, String> profile) {
        final UserPublisher pub = mock(UserPublisher.class);
        when(pub.getClaimProfile("u-1")).thenReturn(profile);
        // The real mapping file is on the test classpath (main/resources).
        return new UserInfoService(pub, "/mapping/claim-oidc-mapping.json");
    }

    @Test
    void unmappedAttribute_keepsItsName_notItsValueAsTheClaimName() {
        final Map<String, String> profile = new LinkedHashMap<>();
        profile.put("department", "Tax");
        final Map<String, String> claims = serviceWith(profile).getOidcClaimProfile("u-1");

        assertThat(claims).containsEntry("department", "Tax");
        assertThat(claims).doesNotContainKey("Tax"); // the old bug produced {"Tax":"Tax"}
    }

    @Test
    void attributeWhoseValueLooksLikeSub_doesNotCreateASubClaim() {
        final Map<String, String> profile = new LinkedHashMap<>();
        profile.put("customField", "sub"); // value "sub" must NOT become the claim name
        final Map<String, String> claims = serviceWith(profile).getOidcClaimProfile("u-1");

        assertThat(claims).containsEntry("customField", "sub");
        assertThat(claims).doesNotContainKey("sub");
    }

    @Test
    void reservedClaims_fromUserAttributes_areDropped() {
        final Map<String, String> profile = new LinkedHashMap<>();
        profile.put("sub", "victim-id");      // mapped sub->sub, but reserved -> dropped
        profile.put("roles", "admin");        // reserved -> dropped
        profile.put("aud", "someone-else");   // reserved -> dropped
        profile.put("email", "alice@example.com"); // standard profile claim -> kept
        final Map<String, String> claims = serviceWith(profile).getOidcClaimProfile("u-1");

        assertThat(claims).doesNotContainKeys("sub", "roles", "aud");
        assertThat(claims).containsEntry("email", "alice@example.com");
    }

    @Test
    void mappedProfileAttributes_areTranslatedToStandardOidcClaims() {
        final Map<String, String> profile = new LinkedHashMap<>();
        profile.put("firstName", "Alice");
        profile.put("username", "alice");
        final Map<String, String> claims = serviceWith(profile).getOidcClaimProfile("u-1");

        assertThat(claims).containsEntry("given_name", "Alice");
        assertThat(claims).containsEntry("preferred_username", "alice");
    }
}
