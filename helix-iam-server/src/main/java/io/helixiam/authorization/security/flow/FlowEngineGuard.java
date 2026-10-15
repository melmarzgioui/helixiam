/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.security.flow;

import io.helixiam.authorization.amqp.AuthFlowPublisher;
import io.helixiam.authorization.flow.persistence.AuthExecutionDefinition;
import io.helixiam.authorization.flow.persistence.AuthFlowDefinition;
import io.helixiam.authorization.support.RealmScopedKey;
import io.helixiam.common.log.LogSafe;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.Collection;
import java.util.Set;

/**
 * Security review item 3: with the flow engine off ({@code helix.flow-engine.enabled=false}) a password login never
 * runs flow steps. A flow that relies on one of the steps listed in {@link #ENGINE_ONLY_STEPS} (the EUDI wallet
 * verification) must then not be completed silently: the password success handler asks {@link #needsEngine} and
 * refuses the login. A flow store that cannot be read at all is logged and does not block password logins (the
 * engine-off path never used the store).
 */
public final class FlowEngineGuard {

    /** Steps that only the flow engine runs and that a login must never skip. */
    public static final Set<String> ENGINE_ONLY_STEPS = Set.of("eudi-wallet-verify");

    private static final Logger LOG = LogManager.getLogger(FlowEngineGuard.class);

    private FlowEngineGuard() {
    }

    /** Whether {@code executions} contain a step only the flow engine runs. */
    public static boolean needsEngine(final Collection<AuthExecutionDefinition> executions) {
        return executions != null && executions.stream()
                .anyMatch(e -> e != null && ENGINE_ONLY_STEPS.contains(e.getAuthenticatorId()));
    }

    /** Whether the login of {@code clientId} (or, without a client, the realm's browser flow) needs the engine. */
    public static boolean needsEngine(final AuthFlowPublisher flows, final String realm, final String clientId) {
        try {
            final AuthFlowDefinition definition = clientId != null && !clientId.isBlank()
                    ? flows.retrieveFlowForClient(RealmScopedKey.pack(realm, clientId))
                    : flows.retrieveBrowserFlow(realm);
            return definition != null && needsEngine(definition.getExecutions());
        } catch (final RuntimeException e) {
            LOG.warn("Could not read the login flow of realm {} to check it: {}", LogSafe.sanitize(realm),
                    e.getClass().getSimpleName());
            return false;
        }
    }
}
