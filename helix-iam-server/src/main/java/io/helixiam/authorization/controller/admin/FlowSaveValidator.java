/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.controller.admin;

import io.helixiam.authorization.amqp.flow.FlowExecutionDto;
import io.helixiam.authorization.federation.wallet.WalletVerifyAuthenticator;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * The per-step settings a flow save must carry (400 {@code {message, fieldErrors}}, field
 * {@code executions[<index>].config.<key>}). Today: the EUDI wallet verification step ({@code eudi-wallet-verify}) names
 * its verify-only wallet connection. Whether that alias IS a verify-only connection is checked when the step runs
 * (connections reload independently of flows), which then fails closed.
 */
final class FlowSaveValidator {

    private static final Pattern ALIAS = Pattern.compile("[A-Za-z0-9._-]{1,64}");

    private FlowSaveValidator() {
    }

    /** Field → message; empty when the executions may be saved. */
    static Map<String, String> validate(final List<FlowExecutionDto> executions) {
        final Map<String, String> errors = new LinkedHashMap<>();
        for (int i = 0; i < executions.size(); i++) {
            final FlowExecutionDto execution = executions.get(i);
            if (execution != null && WalletVerifyAuthenticator.ID.equals(execution.authenticatorId())) {
                final String alias = execution.config() == null ? null
                        : execution.config().get(WalletVerifyAuthenticator.PROVIDER_ALIAS);
                final String field = "executions[" + i + "].config." + WalletVerifyAuthenticator.PROVIDER_ALIAS;
                if (alias == null || alias.isBlank()) {
                    errors.put(field, "Choose the verify-only wallet connection this step uses.");
                } else if (!ALIAS.matcher(alias.trim()).matches()) {
                    errors.put(field, "The wallet connection must be an identity provider alias.");
                }
            }
        }
        return errors;
    }

    /** @throws ProviderValidationException when {@link #validate} finds a problem */
    static List<FlowExecutionDto> requireValid(final List<FlowExecutionDto> executions) {
        final Map<String, String> errors = validate(executions);
        if (!errors.isEmpty()) {
            throw new ProviderValidationException(errors);
        }
        return executions;
    }
}
