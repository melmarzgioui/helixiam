/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.domain;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class UserRegisterTest {

    @Test
    void attributes_serializeAsTopLevelJsonKeys() throws Exception {
        final UserRegister reg = new UserRegister();
        reg.setUsername("alice@acme.nl");
        reg.putAttribute("given_name", "Alice");
        reg.putAttribute("family_name", "de Vries");

        final String json = new ObjectMapper().writeValueAsString(reg);

        // @JsonAnyGetter flattens the map so UserCredentials' @JsonAnySetter picks the keys up.
        assertThat(json).contains("\"given_name\":\"Alice\"");
        assertThat(json).contains("\"family_name\":\"de Vries\"");
        assertThat(reg.getAttributes()).containsEntry("given_name", "Alice");
    }
}
