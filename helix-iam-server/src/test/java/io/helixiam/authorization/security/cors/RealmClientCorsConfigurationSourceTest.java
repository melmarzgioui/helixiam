/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.security.cors;

import org.junit.jupiter.api.Test;
import org.springframework.web.cors.CorsConfiguration;

import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Helix IAM (CORS): the per-client web-origin allowlist — a browser origin is allowed only when it
 * appears in some client's configured web origins for the realm.
 */
class RealmClientCorsConfigurationSourceTest {

    @Test
    void allowsAndReflectsAnExactlyMatchedOrigin() {
        final CorsConfiguration cfg = RealmClientCorsConfigurationSource.corsConfigFor(
                "https://app.gov.nl", Set.of("https://app.gov.nl", "https://other.gov.nl"));

        assertNotNull(cfg);
        assertEquals(java.util.List.of("https://app.gov.nl"), cfg.getAllowedOrigins());
        assertEquals(Boolean.TRUE, cfg.getAllowCredentials());
        assertTrue(cfg.getAllowedMethods().contains("POST"));
    }

    @Test
    void rejectsAnUnlistedOrigin() {
        assertNull(RealmClientCorsConfigurationSource.corsConfigFor(
                "https://evil.example", Set.of("https://app.gov.nl")));
    }

    @Test
    void rejectsWhenNoOriginsAreConfigured() {
        assertNull(RealmClientCorsConfigurationSource.corsConfigFor("https://app.gov.nl", Set.of()));
    }

    @Test
    void rejectsABlankOrigin() {
        assertNull(RealmClientCorsConfigurationSource.corsConfigFor(null, Set.of("https://app.gov.nl")));
        assertNull(RealmClientCorsConfigurationSource.corsConfigFor("  ", Set.of("https://app.gov.nl")));
    }

    /**
     * Security review M2: every config this source builds sets {@code allowCredentials(true)}, so a
     * wildcard entry must NOT turn into reflect-any-origin — that would be a same-origin-policy bypass.
     * A realm whose only entry is {@code *} is treated as having no origins at all.
     */
    @Test
    void aWildcardEntryIsIgnoredAndDeniesUnlistedOrigins() {
        assertNull(RealmClientCorsConfigurationSource.corsConfigFor(
                "https://anything.example", Set.of("*")));
        assertNull(RealmClientCorsConfigurationSource.corsConfigFor(
                "https://evil.example", Set.of("*")));
    }

    /**
     * Security review M2: a stray {@code *} must not disable the rest of the list — explicitly
     * configured origins keep working exactly as before (reflected, with credentials).
     */
    @Test
    void anExplicitOriginStillWorksAlongsideAStrayWildcard() {
        final CorsConfiguration cfg = RealmClientCorsConfigurationSource.corsConfigFor(
                "https://app.gov.nl", Set.of("*", "https://app.gov.nl"));

        assertNotNull(cfg);
        assertEquals(java.util.List.of("https://app.gov.nl"), cfg.getAllowedOrigins());
        assertEquals(Boolean.TRUE, cfg.getAllowCredentials());
    }

    /**
     * Security review M2: the invariant, stated directly — no configuration this source produces may
     * ever pair a wildcard/reflect-any origin with credentials.
     */
    @Test
    void neverCombinesAWildcardOriginWithCredentials() {
        final CorsConfiguration cfg = RealmClientCorsConfigurationSource.corsConfigFor(
                "https://app.gov.nl", Set.of("*", "https://app.gov.nl"));

        assertNotNull(cfg);
        assertTrue(cfg.getAllowCredentials());
        assertTrue(cfg.getAllowedOrigins().stream().noneMatch("*"::equals));
        assertNull(cfg.getAllowedOriginPatterns());
    }
}
