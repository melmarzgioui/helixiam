/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.wallet;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * A stored wallet provider config that cannot be read: a list that is no JSON array of strings, an unknown enum value,
 * or a malformed number or boolean. Carries every malformed field as field → message (the admin API's
 * {@code fieldErrors} shape), so a caller that catches it can still answer {@code 400 {message, fieldErrors}}.
 * Messages name the field and never echo the value.
 */
public class WalletConfigFormatException extends IllegalArgumentException {

    private static final long serialVersionUID = 1L;

    private final Map<String, String> fieldErrors;

    public WalletConfigFormatException(final Map<String, String> fieldErrors) {
        super("Malformed wallet provider config: " + String.join("; ", fieldErrors.values()));
        this.fieldErrors = Collections.unmodifiableMap(new LinkedHashMap<>(fieldErrors));
    }

    /** Field → message, in the order the fields were read. */
    public Map<String, String> fieldErrors() {
        return fieldErrors;
    }
}
