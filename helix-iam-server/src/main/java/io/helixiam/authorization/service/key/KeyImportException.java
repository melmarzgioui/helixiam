/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.service.key;

/**
 * An invalid {@link RealmSigningKeys#importKey} input, naming the import form field it belongs to ({@link #NAME},
 * {@link #PRIVATE_KEY} or {@link #CHAIN}), so the admin API can answer {@code 400 {message, fieldErrors}} with the
 * message on the right field. Still an {@link IllegalArgumentException}: callers that only know the interface contract
 * are unaffected. The message is field-safe (never key material or PEM content).
 */
public class KeyImportException extends IllegalArgumentException {

    /** The key name ({@code [A-Za-z0-9._-]{1,64}}, unique per realm). */
    public static final String NAME = "name";
    /** The PEM private key (format, curve, key type, and the DB_ENCRYPTION requirement for storing it). */
    public static final String PRIVATE_KEY = "privateKeyPem";
    /** The PEM certificate chain (format, order, validity, self-signed leaf, key/leaf match). */
    public static final String CHAIN = "certificateChainPem";

    private final String field;

    public KeyImportException(final String field, final String message) {
        super(message);
        this.field = field;
    }

    /** The import form field the problem belongs to. */
    public String field() {
        return field;
    }
}
