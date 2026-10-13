/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.controller.admin;

import io.helixiam.authorization.service.key.KeyImportException;
import io.helixiam.authorization.service.key.RealmSigningKeys;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Task 24: an import refusal of the key store becomes {@code 400 {message, fieldErrors}} on the form field it names
 * (via {@link ProviderValidationException} and {@link AdminValidationAdvice}), never a 500, including the
 * "set DB_ENCRYPTION first" refusal outside the dev profile.
 */
class VerifierKeyAdminControllerTest {

    private static final String NO_ENCRYPTION =
            "Database encryption is not configured: set DB_ENCRYPTION before importing a verifier signing key";

    @Test
    void aMissingDbEncryptionIsAFieldError_notA500() {
        final RealmSigningKeys keys = mock(RealmSigningKeys.class);
        when(keys.importKey(anyString(), anyString(), anyString(), anyString()))
                .thenThrow(new KeyImportException(KeyImportException.PRIVATE_KEY, NO_ENCRYPTION));
        final VerifierKeyAdminController controller = new VerifierKeyAdminController(keys);

        assertThatThrownBy(() -> controller.importKey("gov",
                new VerifierKeyImportRequest("k", "-----BEGIN PRIVATE KEY-----", "-----BEGIN CERTIFICATE-----"),
                new MockHttpServletRequest()))
                .isInstanceOfSatisfying(ProviderValidationException.class, e -> {
                    assertThat(e.fieldErrors()).containsEntry("privateKeyPem", NO_ENCRYPTION);
                    assertThat(new AdminValidationAdvice().onProviderInvalid(e)).containsEntry("message", NO_ENCRYPTION);
                });
    }

    @Test
    void anUntaggedRefusalIsReportedOnTheChain_withItsFieldSafeMessage() {
        final RealmSigningKeys keys = mock(RealmSigningKeys.class);
        when(keys.importKey(anyString(), anyString(), anyString(), anyString()))
                .thenThrow(new IllegalArgumentException("The certificate chain must be ordered leaf first"));
        final VerifierKeyAdminController controller = new VerifierKeyAdminController(keys);

        assertThatThrownBy(() -> controller.importKey("gov",
                new VerifierKeyImportRequest("k", "key", "chain"), new MockHttpServletRequest()))
                .isInstanceOfSatisfying(ProviderValidationException.class, e -> assertThat(e.fieldErrors())
                        .containsEntry("certificateChainPem", "The certificate chain must be ordered leaf first"));
    }
}
