/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.flow.persistence;

import io.helixiam.authorization.flow.AuthExecution;
import io.helixiam.authorization.flow.AuthFlow;
import io.helixiam.authorization.flow.Requirement;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

/**
 * Helix IAM E2.5: rebuilds the engine's {@link AuthFlow} tree from the flat persisted
 * {@link AuthFlowDefinition}. Children link to parents via {@code parentId}; siblings are
 * ordered by {@code priority}; a node with children becomes a sub-flow, a {@code condition}
 * leaf becomes a condition execution, any other leaf an authenticator execution.
 */
public class AuthFlowMapper {

    public AuthFlow toAuthFlow(final AuthFlowDefinition definition) {
        if (definition == null) {
            return null;
        }
        final List<AuthExecution> top = childrenOf(null, definition.getExecutions());
        return AuthFlow.of(definition.getAlias(), top.toArray(new AuthExecution[0]));
    }

    private List<AuthExecution> childrenOf(final String parentId,
                                           final List<AuthExecutionDefinition> all) {
        final List<AuthExecution> result = new ArrayList<>();
        all.stream()
                .filter(e -> java.util.Objects.equals(e.getParentId(), parentId))
                .sorted(Comparator.comparingInt(AuthExecutionDefinition::getPriority))
                .forEach(e -> result.add(toExecution(e, all)));
        return result;
    }

    private AuthExecution toExecution(final AuthExecutionDefinition def,
                                      final List<AuthExecutionDefinition> all) {
        final List<AuthExecution> children = childrenOf(def.getId(), all);
        if (!children.isEmpty()) {
            final AuthFlow subFlow = AuthFlow.of(def.getId(), children.toArray(new AuthExecution[0]));
            return AuthExecution.subFlow(def.getId(), requirement(def.getRequirement()), subFlow);
        }
        if (def.isCondition()) {
            return AuthExecution.condition(def.getId(), def.getAuthenticatorId());
        }
        return AuthExecution.authenticator(def.getId(), def.getAuthenticatorId(),
                requirement(def.getRequirement()),
                def.getConfig() == null ? java.util.Map.of() : def.getConfig());
    }

    private Requirement requirement(final String value) {
        return Requirement.valueOf(value);
    }
}
