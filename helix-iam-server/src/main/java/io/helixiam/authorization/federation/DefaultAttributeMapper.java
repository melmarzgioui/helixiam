/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation;

import io.helixiam.authorization.federation.spi.AttributeMapper;
import io.helixiam.authorization.federation.spi.BrokeredIdentity;

import java.util.HashMap;
import java.util.Map;

/**
 * Helix IAM E5.1: default {@link AttributeMapper} — normalizes the common identity fields (email +
 * standard name claims) into the local attribute names used for JIT provisioning, deriving a
 * username when the provider didn't supply one. A realm/provider can replace it with a custom bean.
 */
public class DefaultAttributeMapper implements AttributeMapper {

    @Override
    public Map<String, String> map(final BrokeredIdentity identity) {
        final Map<String, String> source = identity.attributes() == null ? Map.of() : identity.attributes();
        final Map<String, String> mapped = new HashMap<>();

        if (identity.email() != null) {
            mapped.put("email", identity.email());
        }
        copyFirst(source, mapped, "firstName", "given_name", "givenName", "firstName");
        copyFirst(source, mapped, "lastName", "family_name", "familyName", "lastName", "surname");

        final String username = firstNonBlank(
                source.get("preferred_username"), source.get("username"), identity.email(), identity.externalSubject());
        mapped.put("username", username);
        return mapped;
    }

    private static void copyFirst(final Map<String, String> source, final Map<String, String> target,
                                  final String targetKey, final String... sourceKeys) {
        for (final String key : sourceKeys) {
            final String value = source.get(key);
            if (value != null && !value.isBlank()) {
                target.put(targetKey, value);
                return;
            }
        }
    }

    private static String firstNonBlank(final String... values) {
        for (final String value : values) {
            if (value != null && !value.isBlank()) {
                return value;
            }
        }
        return null;
    }
}
