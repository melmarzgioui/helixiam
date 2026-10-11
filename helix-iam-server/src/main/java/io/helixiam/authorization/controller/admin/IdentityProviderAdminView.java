/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.controller.admin;

import io.helixiam.authorization.amqp.federation.IdentityProviderConfig;
import io.helixiam.authorization.federation.ProviderSecretKeys;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * An identity-provider connection as the admin API returns it (Task 4, security): the config map without any secret
 * value. Each secret key of the protocol ({@link ProviderSecretKeys}), and any other secret key the stored config
 * carries, is reported as {@code "<key>Set": true|false} instead.
 */
public record IdentityProviderAdminView(String realmId, String alias, String protocol, String displayName,
                                        boolean enabled, Map<String, Object> config) {

    public static IdentityProviderAdminView of(final IdentityProviderConfig c) {
        final Map<String, String> source = c.config() == null ? Map.of() : c.config();
        final Map<String, Object> config = new LinkedHashMap<>();
        source.forEach((k, v) -> {
            if (k != null && !ProviderSecretKeys.isSecret(c.protocol(), k) && !ProviderSecretKeys.isControlKey(k)) {
                config.put(k, v);
            }
        });
        for (final String key : ProviderSecretKeys.keysFor(c.protocol())) {
            config.put(ProviderSecretKeys.setFlag(key), isSet(source.get(key)));
        }
        source.forEach((k, v) -> {
            if (ProviderSecretKeys.isSecret(c.protocol(), k)) {
                config.putIfAbsent(ProviderSecretKeys.setFlag(k), isSet(v));
            }
        });
        return new IdentityProviderAdminView(c.realmId(), c.alias(), c.protocol(), c.displayName(), c.enabled(),
                config);
    }

    private static boolean isSet(final String value) {
        return value != null && !value.isBlank();
    }
}
