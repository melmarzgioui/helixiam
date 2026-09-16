/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.security.fapi;

import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Helix IAM B11 (FAPI / RFC 8705): the {@code cnf} (confirmation) claim carries the certificate
 * thumbprint {@code x5t#S256} so a resource server can prove the bearer presents the bound certificate.
 * It must coexist with a DPoP {@code jkt} (RFC 9449) when both apply, and — critically — be a MUTABLE
 * map: the SAS Jackson allowlist rejects immutable collections (Map.of/List.of) in token claims.
 */
class MtlsConfirmationTest {

    @Test
    void buildsCnfWithThumbprintWhenNonePresent() {
        final Map<String, Object> cnf = MtlsConfirmation.mergeX5t(null, "ABC123");
        assertThat(cnf).containsEntry("x5t#S256", "ABC123");
    }

    @Test
    void preservesAnExistingDpopJktAlongsideTheThumbprint() {
        final Map<String, Object> existing = new HashMap<>();
        existing.put("jkt", "dpop-key-thumb");
        final Map<String, Object> cnf = MtlsConfirmation.mergeX5t(existing, "ABC123");
        assertThat(cnf).containsEntry("jkt", "dpop-key-thumb").containsEntry("x5t#S256", "ABC123");
    }

    @Test
    void returnsAMutableMap() {
        final Map<String, Object> cnf = MtlsConfirmation.mergeX5t(Map.of("jkt", "k"), "ABC123");
        // must not throw — SAS would reject an immutable map at token serialization
        cnf.put("extra", "ok");
        assertThat(cnf).containsKey("extra");
    }
}
