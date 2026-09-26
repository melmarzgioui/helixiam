/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.service.authz;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.assertThat;

/** 1.0 item 3: a permission's type is parsed case-insensitively into a closed set; anything else is unknown. */
class PermissionTypeTest {

    @ParameterizedTest
    @CsvSource({"scope,SCOPE", "Scope,SCOPE", "SCOPE,SCOPE", " sCoPe ,SCOPE",
            "resource,RESOURCE", "Resource,RESOURCE", "RESOURCE,RESOURCE", "rEsOuRcE,RESOURCE"})
    void knownTypes_parseIgnoringCaseAndWhitespace(final String raw, final PermissionType expected) {
        assertThat(PermissionType.parse(raw)).contains(expected);
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {"  ", "bogus", "scopes", "resources", "role", "*"})
    void anythingElse_isUnknown(final String raw) {
        assertThat(PermissionType.parse(raw)).isEmpty();
    }
}
