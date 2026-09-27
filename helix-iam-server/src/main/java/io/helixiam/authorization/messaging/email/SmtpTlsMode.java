/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.messaging.email;

import java.util.Locale;

/**
 * How the SMTP driver protects the connection.
 * <ul>
 *   <li>{@link #STARTTLS_REQUIRED} (default): plain connect, then STARTTLS; a server without STARTTLS is refused;</li>
 *   <li>{@link #STARTTLS_OPTIONAL}: STARTTLS when the server offers it, else plain text;</li>
 *   <li>{@link #IMPLICIT}: TLS from the first byte ("SMTPS", usually port 465);</li>
 *   <li>{@link #NONE}: plain text, for local development only (refused unless the server runs with the {@code dev}
 *       profile).</li>
 * </ul>
 * The deprecated boolean {@code starttls} maps {@code true} to {@link #STARTTLS_REQUIRED} and {@code false} to
 * {@link #STARTTLS_OPTIONAL}; {@code tlsMode} wins when both are set.
 */
public enum SmtpTlsMode {
    STARTTLS_REQUIRED, STARTTLS_OPTIONAL, IMPLICIT, NONE;

    /**
     * The mode for a provider's {@code tlsMode} and deprecated {@code starttls} settings.
     *
     * @throws IllegalArgumentException for an unknown {@code tlsMode} or a {@code starttls} that is not a boolean
     */
    public static SmtpTlsMode resolve(final String tlsMode, final String legacyStarttls) {
        if (tlsMode != null && !tlsMode.isBlank()) {
            try {
                return valueOf(tlsMode.trim().toUpperCase(Locale.ROOT));
            } catch (final IllegalArgumentException e) {
                throw new IllegalArgumentException("Unknown tlsMode; use STARTTLS_REQUIRED, STARTTLS_OPTIONAL, "
                        + "IMPLICIT or NONE", e);
            }
        }
        if (legacyStarttls != null && !legacyStarttls.isBlank()) {
            final String v = legacyStarttls.trim().toLowerCase(Locale.ROOT);
            if ("true".equals(v)) {
                return STARTTLS_REQUIRED;
            }
            if ("false".equals(v)) {
                return STARTTLS_OPTIONAL;
            }
            throw new IllegalArgumentException("starttls must be true or false");
        }
        return STARTTLS_REQUIRED;
    }

    /** 465 for implicit TLS, else 587 (submission). */
    public int defaultPort() {
        return this == IMPLICIT ? 465 : 587;
    }
}
