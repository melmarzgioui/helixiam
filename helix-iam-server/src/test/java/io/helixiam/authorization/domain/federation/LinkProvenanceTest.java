/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.domain.federation;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class LinkProvenanceTest {

    @Test
    void unknownProvenanceIsTheLeastTrusted() {
        assertThat(LinkProvenance.normalize(null)).isEqualTo("AUTO");
        assertThat(LinkProvenance.normalize("admin-api")).isEqualTo("AUTO");
        assertThat(LinkProvenance.normalize(" jit ")).isEqualTo("JIT");
        assertThat(LinkProvenance.mayAuthenticateAdmin(null)).isFalse();
        assertThat(LinkProvenance.mayAuthenticateAdmin("AUTO")).isFalse();
        assertThat(LinkProvenance.mayAuthenticateAdmin("SELF")).isTrue();
        assertThat(LinkProvenance.mayAuthenticateAdmin("WALLET")).isTrue();
        assertThat(LinkProvenance.mayAuthenticateAdmin("JIT")).isTrue();
        assertThat(LinkProvenance.mayAuthenticateAdmin("LEGACY")).isTrue();
        assertThat(LinkProvenance.mayAuthenticateAdmin("ADMIN_CONFIRMED")).isTrue();
    }
}
