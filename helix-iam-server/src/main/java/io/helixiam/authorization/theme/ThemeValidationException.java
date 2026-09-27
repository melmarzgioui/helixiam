/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.theme;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * A theme failed validation. Carries field-level errors (JSON path → message); the admin API turns it into
 * {@code 400 {message, fieldErrors}} ({@code AdminValidationAdvice}).
 */
public class ThemeValidationException extends RuntimeException {

    private final transient Map<String, String> fieldErrors;

    public ThemeValidationException(final Map<String, String> fieldErrors) {
        super(first(fieldErrors));
        this.fieldErrors = Collections.unmodifiableMap(new LinkedHashMap<>(fieldErrors));
    }

    public Map<String, String> fieldErrors() {
        return fieldErrors;
    }

    private static String first(final Map<String, String> errors) {
        if (errors == null || errors.isEmpty()) {
            return "The theme is not valid.";
        }
        final Map.Entry<String, String> e = errors.entrySet().iterator().next();
        return e.getKey() + ": " + e.getValue();
    }
}
