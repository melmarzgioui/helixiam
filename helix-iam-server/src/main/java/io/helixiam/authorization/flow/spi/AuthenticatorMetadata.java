/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.flow.spi;

import java.util.List;

/**
 * Helix IAM E2.1: an authenticator's self-description — its stable {@code id} (referenced by
 * flow executions), a display name, the {@link FactorClass} it provides, a level-of-assurance
 * weight, the {@link AuthenticatorCategory category} that tells the console whether it is a
 * sign-in method or a flow condition, and the {@link ConfigProperty config schema} the admin
 * console renders. Pure data.
 */
public record AuthenticatorMetadata(
        String id,
        String displayName,
        FactorClass factorClass,
        int levelOfAssurance,
        AuthenticatorCategory category,
        List<ConfigProperty> configSchema) {

    public AuthenticatorMetadata {
        category = category == null ? AuthenticatorCategory.METHOD : category;
        configSchema = configSchema == null ? List.of() : List.copyOf(configSchema);
    }

    /** Backward-compatible 5-arg form (no explicit category ⇒ {@link AuthenticatorCategory#METHOD}). */
    public AuthenticatorMetadata(final String id, final String displayName, final FactorClass factorClass,
                                 final int levelOfAssurance, final List<ConfigProperty> configSchema) {
        this(id, displayName, factorClass, levelOfAssurance, AuthenticatorCategory.METHOD, configSchema);
    }

    /** A sign-in method with no config schema. */
    public static AuthenticatorMetadata of(final String id, final String displayName,
                                           final FactorClass factorClass, final int levelOfAssurance) {
        return new AuthenticatorMetadata(id, displayName, factorClass, levelOfAssurance,
                AuthenticatorCategory.METHOD, List.of());
    }

    /** A flow condition (predicate that gates a sub-flow) — always {@link FactorClass#NONE}/LoA 0. */
    public static AuthenticatorMetadata condition(final String id, final String displayName) {
        return new AuthenticatorMetadata(id, displayName, FactorClass.NONE, 0,
                AuthenticatorCategory.CONDITION, List.of());
    }
}
