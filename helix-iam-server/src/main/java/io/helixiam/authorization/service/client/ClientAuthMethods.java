/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.service.client;

import java.util.Locale;

/**
 * The token endpoint auth methods a client can be stored with, matched case-insensitively and stored in one spelling:
 * {@code PRIVATE_KEY_JWT} (the console and admin API spelling, which the token endpoint keys on),
 * {@code client_secret_basic} and {@code none} (the DCR spellings). Blank means the default (client secret). Any other
 * value is refused, so a typo can never silently fall back to a client secret.
 */
public final class ClientAuthMethods {

    public static final String PRIVATE_KEY_JWT = "PRIVATE_KEY_JWT";
    public static final String UNKNOWN = "Unknown token endpoint auth method (use private_key_jwt, client_secret_basic"
            + " or none).";
    /** Stable machine-readable code for {@link #UNKNOWN}, so a client can map it to its own translated copy
     * instead of matching the (English-only) {@link #problem} message text. */
    public static final String CODE_UNKNOWN = "unknown";

    private ClientAuthMethods() {
    }

    /** The stored spelling, null for blank; an unknown method throws {@link IllegalArgumentException}. */
    public static String normalize(final String raw) {
        if (raw == null || raw.isBlank()) {
            return null;
        }
        return switch (raw.trim().toLowerCase(Locale.ROOT)) {
            case "private_key_jwt" -> PRIVATE_KEY_JWT;
            case "client_secret_basic" -> "client_secret_basic";
            case "none" -> "none";
            default -> throw new IllegalArgumentException(UNKNOWN);
        };
    }

    /** The field error for {@code tokenEndpointAuthMethod}, or null. */
    public static String problem(final String raw) {
        try {
            normalize(raw);
            return null;
        } catch (final IllegalArgumentException e) {
            return UNKNOWN;
        }
    }

    /** The stable code for {@code tokenEndpointAuthMethod}'s problem ({@link #CODE_UNKNOWN}), or null. */
    public static String code(final String raw) {
        try {
            normalize(raw);
            return null;
        } catch (final IllegalArgumentException e) {
            return CODE_UNKNOWN;
        }
    }

    /** True when {@code stored} means private_key_jwt, in any case. */
    public static boolean isPrivateKeyJwt(final String stored) {
        return stored != null && PRIVATE_KEY_JWT.equalsIgnoreCase(stored.trim());
    }
}
