/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.controller.admin;

import java.util.LinkedHashMap;
import java.util.Map;

/** A messaging provider that cannot be saved: one message per invalid field (400 via {@link AdminValidationAdvice}). */
public class ProviderValidationException extends RuntimeException {

    private final transient Map<String, String> fieldErrors;

    public ProviderValidationException(final Map<String, String> fieldErrors) {
        super(fieldErrors.isEmpty() ? "The provider is not valid." : fieldErrors.values().iterator().next());
        this.fieldErrors = new LinkedHashMap<>(fieldErrors);
    }

    public Map<String, String> fieldErrors() {
        return fieldErrors;
    }
}
