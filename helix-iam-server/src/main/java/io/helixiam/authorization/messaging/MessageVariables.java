/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.messaging;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Helix IAM notifications (N6a): builds the variable map handed to {@link TemplateRenderer}, exposing every
 * claim of the bound user under a {@code user.} namespace (e.g. {@code {{user.email}}},
 * {@code {{user.given_name}}}, {@code {{user.preferred_username}}}). System variables ({@code realm},
 * {@code code}, {@code ttl}, {@code link}, {@code number}, and the legacy display-name {@code user}) always
 * win on collision, so a tenant's custom claim can never clobber the OTP code or realm name. Pure +
 * side-effect-free.
 */
public final class MessageVariables {

    /** Namespace prefix under which a user's claims are exposed to templates. */
    public static final String USER_CLAIM_PREFIX = "user.";

    private MessageVariables() {
    }

    /**
     * Merge the user's claim {@code profile} (namespaced under {@code user.}) with the system {@code base}
     * vars. {@code base} takes precedence so a claim literally named e.g. {@code code} stays available only as
     * {@code user.code} and never overrides the system {@code code}.
     */
    public static Map<String, String> withUserClaims(final Map<String, String> base, final Map<String, String> profile) {
        final Map<String, String> out = new LinkedHashMap<>();
        if (profile != null) {
            profile.forEach((key, value) -> {
                if (key != null && !key.isBlank() && value != null) {
                    out.put(USER_CLAIM_PREFIX + key, value);
                }
            });
        }
        if (base != null) {
            out.putAll(base);
        }
        return out;
    }
}
