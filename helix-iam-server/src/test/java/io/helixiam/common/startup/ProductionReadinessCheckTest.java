/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.common.startup;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;
import org.springframework.core.env.Environment;
import org.springframework.mock.env.MockEnvironment;

class ProductionReadinessCheckTest {

    private static Environment env(final boolean dev) {
        final MockEnvironment e = new MockEnvironment();
        if (dev) {
            e.setActiveProfiles("dev");
        }
        return e;
    }

    /** A fully-configured, secure production posture. */
    private static ProductionReadinessCheck secureProd(final String encKey, final boolean allowPlaintext,
                                                       final String idp, final String sp) {
        return new ProductionReadinessCheck(env(false), encKey, allowPlaintext, idp, sp,
                false, false, true, false, false);
    }

    @Test
    void failsFast_whenEncryptionUnset_outsideDev_withoutOptIn() {
        final ProductionReadinessCheck c = secureProd("", false, "https://idp", "https://sp");
        assertThatThrownBy(c::check)
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("DB_ENCRYPTION");
    }

    @Test
    void allowsPlaintext_whenExplicitlyOptedIn() {
        final ProductionReadinessCheck c = secureProd("", true, "https://idp", "https://sp");
        assertThatCode(c::check).doesNotThrowAnyException();
    }

    @Test
    void failsFast_whenBaseUrlsUnset_outsideDev() {
        assertThatThrownBy(() -> secureProd("deadbeef", false, "", "https://sp").check())
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("IDP_BASE_URL");
        assertThatThrownBy(() -> secureProd("deadbeef", false, "https://idp", "").check())
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("SP_BASE_URL");
    }

    @Test
    void devProfile_downgradesEveryFatalCheck() {
        final ProductionReadinessCheck c = new ProductionReadinessCheck(env(true),
                "", false, "", "", true, true, false, true, true);
        assertThatCode(c::check).doesNotThrowAnyException();
    }

    @Test
    void secureProdPosture_startsCleanly() {
        final ProductionReadinessCheck c = secureProd("deadbeefdeadbeef", false, "https://idp", "https://sp");
        assertThatCode(c::check).doesNotThrowAnyException();
    }
}
