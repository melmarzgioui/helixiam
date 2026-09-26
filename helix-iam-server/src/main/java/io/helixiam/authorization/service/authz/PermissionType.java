/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.service.authz;

import java.util.Locale;
import java.util.Optional;

/**
 * The closed set of authorization-permission types. Stored and imported values arrive in any case
 * (Keycloak exports use {@code "scope"}/{@code "resource"}); {@link #parse} is the single place that decides
 * what a value means. Anything it does not recognise is unknown — refused on save and denied at evaluation.
 */
public enum PermissionType {
    RESOURCE,
    SCOPE;

    public static Optional<PermissionType> parse(final String raw) {
        if (raw == null || raw.isBlank()) {
            return Optional.empty();
        }
        try {
            return Optional.of(valueOf(raw.trim().toUpperCase(Locale.ROOT)));
        } catch (final IllegalArgumentException unknown) {
            return Optional.empty();
        }
    }
}
