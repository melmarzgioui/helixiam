/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.security.session;

import org.junit.jupiter.api.Test;

import java.time.Instant;

import static io.helixiam.testsupport.Jackson2Fixtures.assertWritesSame;
import static io.helixiam.testsupport.Jackson2Fixtures.read;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * Jackson 3 upgrade: a verify-only wallet step that released its claims just before the upgrade left them in the
 * sign-in session, wrapped by the Jackson 2 line ({@link PendingVerifiedClaims#wrap}); the code exchange after the
 * upgrade must still release exactly those claims.
 */
class PendingVerifiedClaimsUpgradeTest {

    private static final String CLAIMS = "{\"verification\":{\"trust_framework\":\"eidas\",\"assurance_level\":"
            + "\"high\",\"time\":\"2026-10-01T10:00:00Z\"},\"claims\":{\"given_name\":\"Zoë\",\"age_over_18\":true,"
            + "\"address\":{\"locality\":\"Den Haag / ’s-Gravenhage\"},\"n\":12,\"big\":12345678901,\"f\":1.5,"
            + "\"none\":null,\"list\":[\"a\",1,false]}}";
    private static final Instant EXPIRES = Instant.parse("2026-10-01T10:05:00Z");

    @Test
    void pendingClaimsWrappedByTheJackson2Line_areReleasedUnchanged() {
        final String hash = PendingVerifiedClaims.requestHash("web", "state-1", "nonce-1", "https://app.example.eu/cb");
        assertWritesSame("pending-verified-claims.json", PendingVerifiedClaims.wrap(CLAIMS, "web", hash, EXPIRES));

        assertWritesSame("pending-verified-claims-released.json", PendingVerifiedClaims.claimsFor(
                read("pending-verified-claims.json"), "web", hash, EXPIRES.minusSeconds(1)).orElseThrow());
        assertThat(PendingVerifiedClaims.claimsFor(read("pending-verified-claims.json"), "web", hash, EXPIRES))
                .isEmpty();
        assertThat(PendingVerifiedClaims.claimsFor(read("pending-verified-claims.json"), "other", hash,
                EXPIRES.minusSeconds(1))).isEmpty();
    }
}
