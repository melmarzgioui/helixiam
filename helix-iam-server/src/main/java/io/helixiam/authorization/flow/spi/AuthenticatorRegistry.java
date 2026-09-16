/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.flow.spi;

import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Helix IAM E2.3: catalogue of installed {@link Authenticator}s, keyed by their stable id.
 * Flow executions reference authenticators by id; the runtime resolves them here, and the
 * admin console lists {@link #all()} to let an admin compose flows.
 */
public class AuthenticatorRegistry {

    private final Map<String, Authenticator> byId = new LinkedHashMap<>();

    public AuthenticatorRegistry(final Collection<Authenticator> authenticators) {
        for (final Authenticator authenticator : authenticators) {
            final String id = authenticator.metadata().id();
            if (byId.containsKey(id)) {
                throw new IllegalArgumentException("Duplicate authenticator id: " + id);
            }
            byId.put(id, authenticator);
        }
    }

    public Authenticator get(final String id) {
        final Authenticator authenticator = byId.get(id);
        if (authenticator == null) {
            throw new IllegalArgumentException("No authenticator registered with id: " + id);
        }
        return authenticator;
    }

    public List<Authenticator> all() {
        return List.copyOf(byId.values());
    }
}
