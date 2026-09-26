/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.controller.admin;

import static org.assertj.core.api.Assertions.assertThat;

import jakarta.validation.Validation;
import jakarta.validation.Validator;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/** 1.0 security (item 1): a protocol mapper can never be saved with a reserved claim name. */
class NotReservedClaimTest {

    private static final Validator VALIDATOR = Validation.buildDefaultValidatorFactory().getValidator();

    @ParameterizedTest
    @ValueSource(strings = {"sub", "iss", "aud", "exp", "iat", "nbf", "jti", "azp", "sid", "auth_time", "nonce", "acr",
            "amr", "scope", "client_id", "organizations", "realm_access", "resource_access", "act", "may_act", "SUB", " Aud "})
    void reservedClaimNamesAreRejected(final String claim) {
        assertThat(VALIDATOR.validate(new MapperRequest("m", "USER_ATTRIBUTE", "firm", claim, true, true)))
                .extracting(v -> v.getPropertyPath().toString()).containsExactly("claimName");
    }

    @ParameterizedTest
    @ValueSource(strings = {"firm_id", "department", "email_domain"})
    void ordinaryClaimNamesAreAccepted(final String claim) {
        assertThat(VALIDATOR.validate(new MapperRequest("m", "USER_ATTRIBUTE", "firm", claim, true, true))).isEmpty();
    }
}
