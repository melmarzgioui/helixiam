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

    @Test
    void aWildcardEntryReflectsAnyOrigin() {
        final CorsConfiguration cfg = RealmClientCorsConfigurationSource.corsConfigFor(
                "https://anything.example", Set.of("*"));

        assertNotNull(cfg);
        assertEquals(java.util.List.of("https://anything.example"), cfg.getAllowedOrigins());
    }
}
