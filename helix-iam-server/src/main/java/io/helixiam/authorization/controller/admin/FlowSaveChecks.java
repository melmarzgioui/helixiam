/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.controller.admin;

import io.helixiam.authorization.amqp.flow.FlowAdminPublisher;
import io.helixiam.authorization.amqp.flow.FlowDefinitionDto;
import io.helixiam.authorization.amqp.flow.FlowExecutionDto;
import io.helixiam.authorization.amqp.flow.FlowRefDto;
import io.helixiam.authorization.federation.IdentityProviderRegistry;
import io.helixiam.authorization.federation.spi.IdentityProvider;
import io.helixiam.authorization.flow.authenticators.IdentityProviderRedirectAuthenticator;
import io.helixiam.authorization.security.flow.FlowEngineGuard;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Server-side checks on what an admin saves into, or binds to, a login flow (400 {@code {message, fieldErrors}}):
 * <ul>
 *   <li>{@link FlowSaveValidator}: the wallet verification step names its connection;</li>
 *   <li>security review item 3b: with the flow engine off a password login never runs flow steps, so a flow with
 *       a step only the engine runs ({@link FlowEngineGuard#ENGINE_ONLY_STEPS}) cannot be saved, nor bound to a client
 *       or application;</li>
 *   <li>security review item 8: an application's single sign-on step ({@code idp-redirect}, REDIRECT/OPTION) never
 *       names a provider that cannot sign anyone in (an EUDI wallet verify-only connection).</li>
 * </ul>
 */
@Component
public class FlowSaveChecks {

    static final String ENGINE_OFF = "This flow has an EU Digital Identity Wallet verification step, which runs only "
            + "with the flow engine on (helix.flow-engine.enabled=true). Turn the engine on first.";

    private final boolean engineEnabled;
    private final FlowAdminPublisher flows;
    private final IdentityProviderRegistry registry;

    public FlowSaveChecks(@Value("${helix.flow-engine.enabled:false}") final boolean engineEnabled,
                          final FlowAdminPublisher flows, final IdentityProviderRegistry registry) {
        this.engineEnabled = engineEnabled;
        this.flows = flows;
        this.registry = registry;
    }

    /** Whether the data-driven flow engine runs after a password login. */
    public boolean engineEnabled() {
        return engineEnabled;
    }

    /** {@code executions} when they may be saved in {@code realmId}; else a {@link ProviderValidationException}. */
    public List<FlowExecutionDto> requireValid(final String realmId, final List<FlowExecutionDto> executions) {
        final Map<String, String> errors = new LinkedHashMap<>(FlowSaveValidator.validate(executions));
        for (int i = 0; i < executions.size(); i++) {
            final FlowExecutionDto e = executions.get(i);
            final int index = i;
            if (e == null) {
                continue;
            }
            if (!engineEnabled && FlowEngineGuard.ENGINE_ONLY_STEPS.contains(e.authenticatorId())) {
                errors.putIfAbsent("executions[" + i + "].authenticatorId", ENGINE_OFF);
            }
            if (IdentityProviderRedirectAuthenticator.ID.equals(e.authenticatorId()) && e.config() != null) {
                for (final String key : List.of(IdentityProviderRedirectAuthenticator.PROVIDER_ALIAS,
                        IdentityProviderRedirectAuthenticator.PROVIDER_ALIASES)) {
                    final String value = e.config().get(key);
                    if (value == null) {
                        continue;
                    }
                    Arrays.stream(value.split(",")).map(String::trim).filter(a -> !a.isEmpty())
                            .filter(a -> !signInCapable(realmId, a)).findFirst().ifPresent(a ->
                                    errors.putIfAbsent("executions[" + index + "].config." + key, "'" + a
                                            + "' is a verify-only wallet connection: it cannot sign anyone in."));
                }
            }
        }
        if (!errors.isEmpty()) {
            throw new ProviderValidationException(errors);
        }
        return executions;
    }

    /** Refuses binding {@code flowAlias} (field {@code field}) when it needs the engine and the engine is off. */
    public void requireBindable(final String realmId, final String flowAlias, final String field) {
        if (engineEnabled || flowAlias == null || flowAlias.isBlank()) {
            return;
        }
        final FlowDefinitionDto flow;
        try {
            flow = flows.getByAlias(new FlowRefDto(realmId, flowAlias.trim()));
        } catch (final RuntimeException absent) {
            return; // an unknown flow is the existing behaviour's business, not this check's
        }
        if (flow != null && flow.executions() != null && flow.executions().stream()
                .anyMatch(e -> e != null && FlowEngineGuard.ENGINE_ONLY_STEPS.contains(e.authenticatorId()))) {
            throw new ProviderValidationException(Map.of(field, ENGINE_OFF));
        }
    }

    private boolean signInCapable(final String realmId, final String alias) {
        try {
            final IdentityProvider provider = registry.get(realmId, alias);
            return provider.signInCapable();
        } catch (final IllegalArgumentException unknown) {
            return true; // unknown aliases are not this check's concern
        }
    }
}
