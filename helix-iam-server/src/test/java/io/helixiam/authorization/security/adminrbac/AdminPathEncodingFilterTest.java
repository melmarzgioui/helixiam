/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.security.adminrbac;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class AdminPathEncodingFilterTest {

    @Test
    void refusesEncodingInTheRealmOrRoutePart() {
        assertThat(AdminPathEncodingFilter.refused("/admin/realms/r/k%65ys/import")).isTrue();
        assertThat(AdminPathEncodingFilter.refused("/admin/realms/r/%6Beys")).isTrue();
        assertThat(AdminPathEncodingFilter.refused("/admin/realms/%72/keys")).isTrue();
        assertThat(AdminPathEncodingFilter.refused("/admin/re%61lms/r/keys")).isTrue();
        assertThat(AdminPathEncodingFilter.refused("/admin/%61udit/config")).isTrue();
        assertThat(AdminPathEncodingFilter.refused("/admin%2Frealms/r/keys")).isTrue();
        assertThat(AdminPathEncodingFilter.refused("/admin/realms/r/saml-clients/urn%253Ax")).isTrue();
    }

    @Test
    void allowsPlainPaths_andEncodedIdsDeeperDown() {
        assertThat(AdminPathEncodingFilter.refused("/admin/realms/r/keys/import")).isFalse();
        assertThat(AdminPathEncodingFilter.refused("/admin/realms/r/saml-clients/urn%3Aexample%3Asp")).isFalse();
        assertThat(AdminPathEncodingFilter.refused("/admin/realms/r/clients/c/authz/scopes/read%3Adocs")).isFalse();
        assertThat(AdminPathEncodingFilter.refused("/admin/realms")).isFalse();
        assertThat(AdminPathEncodingFilter.refused("/realms/r/oauth2/token")).isFalse();
        assertThat(AdminPathEncodingFilter.refused("/administrator")).isFalse();
    }
}
