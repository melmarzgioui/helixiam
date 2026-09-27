/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.e2e;

import com.fasterxml.jackson.databind.JsonNode;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The discovery document advertises what A3/A4 deliver: {@code auth_time} and {@code sid} in
 * {@code claims_supported}, and OIDC Back-Channel Logout with session ({@code sid}) support.
 */
class DiscoverySessionMetadataE2eTest extends AbstractE2eTest {

    @Test
    void discoveryAdvertisesSessionClaims_andBackchannelLogout_inEveryRealm() {
        final String realm = E2eSeed.unique("disc");
        seed().realm(realm);
        for (final String r : List.of(MASTER, realm)) {
            final JsonNode doc = oidc(r).discovery();
            final List<String> claims = new ArrayList<>();
            doc.path("claims_supported").forEach(c -> claims.add(c.asText()));
            assertThat(claims).as("claims_supported in %s: %s", r, doc).contains("sub", "iss", "auth_time", "sid");
            assertThat(doc.path("backchannel_logout_supported").asBoolean()).as(doc.toString()).isTrue();
            assertThat(doc.path("backchannel_logout_session_supported").asBoolean()).as(doc.toString()).isTrue();
            // Existing metadata is untouched by the customizer.
            assertThat(doc.path("end_session_endpoint").asText()).endsWith("/realms/" + r + "/connect/logout");
            assertThat(doc.path("id_token_signing_alg_values_supported").toString()).contains("RS256", "PS256");
        }
    }
}
