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

    // --- review #4: the plaintext-read migration mode is time-boxed outside dev ----------------------

    private static final java.time.Clock TODAY = java.time.Clock.fixed(
            java.time.Instant.parse("2026-10-12T10:00:00Z"), java.time.ZoneOffset.UTC);

    private static ProductionReadinessCheck migrating(final boolean dev, final String until) {
        return new ProductionReadinessCheck(env(dev), "deadbeefdeadbeef", false, "https://idp", "https://sp",
                false, false, true, false, false, true, until, TODAY);
    }

    @Test
    void migrationMode_outsideDev_withoutAnEndDate_isFatal() {
        assertThatThrownBy(() -> migrating(false, "").check())
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("HELIX_DB_ENCRYPTION_MIGRATE_PLAINTEXT")
                .hasMessageContaining("HELIX_DB_ENCRYPTION_MIGRATE_UNTIL");
    }

    @Test
    void migrationMode_outsideDev_withAnEndDateWithin30Days_starts() {
        assertThatCode(() -> migrating(false, "2026-10-12").check()).doesNotThrowAnyException();
        assertThatCode(() -> migrating(false, "2026-11-11").check()).doesNotThrowAnyException();
    }

    @Test
    void migrationMode_outsideDev_withAnEndDateTooFarAheadPastOrMalformed_isFatal() {
        assertThatThrownBy(() -> migrating(false, "2026-11-12").check()).isInstanceOf(IllegalStateException.class);
        assertThatThrownBy(() -> migrating(false, "2026-10-11").check()).isInstanceOf(IllegalStateException.class);
        assertThatThrownBy(() -> migrating(false, "next week").check()).isInstanceOf(IllegalStateException.class);
    }

    @Test
    void migrationMode_inDev_isNotFatal() {
        assertThatCode(() -> migrating(true, "").check()).doesNotThrowAnyException();
    }

    @Test
    void allowPlaintextSecrets_withAKey_isNotTheMigrationMode() {
        // HELIX_ALLOW_PLAINTEXT_SECRETS only accepts running WITHOUT a key; with a key set it changes nothing.
        final ProductionReadinessCheck c = secureProd("deadbeefdeadbeef", true, "https://idp", "https://sp");
        assertThatCode(c::check).doesNotThrowAnyException();
    }
}
