/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.flow.spi;

import java.util.List;

/**
 * Helix IAM E2.1: one configurable setting an authenticator (or any SPI provider) declares,
 * so the admin console can render a settings form generically — the dashboard reads the
 * {@link AuthenticatorMetadata#configSchema()} and builds inputs from these descriptors.
 */
public record ConfigProperty(
        String key,
        String label,
        Type type,
        boolean required,
        String defaultValue,
        List<String> options) {

    public enum Type {STRING, BOOLEAN, INTEGER, SECRET, SELECT}

    public ConfigProperty {
        options = options == null ? List.of() : List.copyOf(options);
    }

    public static ConfigProperty string(final String key, final String label, final boolean required) {
        return new ConfigProperty(key, label, Type.STRING, required, null, List.of());
    }

    public static ConfigProperty bool(final String key, final String label, final boolean defaultValue) {
        return new ConfigProperty(key, label, Type.BOOLEAN, false, Boolean.toString(defaultValue), List.of());
    }

    public static ConfigProperty integer(final String key, final String label, final boolean required) {
        return new ConfigProperty(key, label, Type.INTEGER, required, null, List.of());
    }

    public static ConfigProperty select(final String key, final String label, final List<String> options) {
        return new ConfigProperty(key, label, Type.SELECT, false, null, options);
    }
}
