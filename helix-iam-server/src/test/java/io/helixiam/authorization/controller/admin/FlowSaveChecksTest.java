/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.controller.admin;

import io.helixiam.authorization.amqp.flow.FlowAdminPublisher;
import io.helixiam.authorization.amqp.flow.FlowDefinitionDto;
import io.helixiam.authorization.amqp.flow.FlowExecutionDto;
import io.helixiam.authorization.federation.IdentityProviderRegistry;
import io.helixiam.authorization.federation.spi.IdentityProvider;
import io.helixiam.authorization.federation.spi.IdpMetadata;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/** Security review items 3b and 8: what a flow save or a flow binding may not contain. */
class FlowSaveChecksTest {

    private final FlowAdminPublisher flows = mock(FlowAdminPublisher.class);

    private static FlowExecutionDto step(final String authenticator, final Map<String, String> config) {
        return new FlowExecutionDto("e1", null, authenticator, "REQUIRED", false, 10, config);
    }

    private static IdentityProvider provider(final String alias, final boolean signIn) {
        final IdentityProvider p = mock(IdentityProvider.class);
        when(p.metadata()).thenReturn(IdpMetadata.of(alias, IdpMetadata.Protocol.WALLET, alias, null, null));
        when(p.signInCapable()).thenReturn(signIn);
        return p;
    }

    private FlowSaveChecks checks(final boolean engine) {
        final IdentityProviderRegistry registry = new IdentityProviderRegistry(List.of());
        registry.reload("acme", List.of(provider("eudi-wallet", true), provider("eudi-verify", false)));
        return new FlowSaveChecks(engine, flows, registry);
    }

    private static final List<FlowExecutionDto> WALLET_STEP = List.of(step("eudi-wallet-verify",
            Map.of("providerAlias", "eudi-verify")));

    @Test
    void aWalletVerificationStep_cannotBeSavedWithTheEngineOff() {
        assertThatThrownBy(() -> checks(false).requireValid("acme", WALLET_STEP))
                .isInstanceOf(ProviderValidationException.class)
                .satisfies(e -> assertThat(((ProviderValidationException) e).fieldErrors())
                        .containsKey("executions[0].authenticatorId"));
        assertThat(checks(true).requireValid("acme", WALLET_STEP)).isEqualTo(WALLET_STEP);
        assertThat(checks(false).requireValid("acme", List.of(step(null, null), step("otp", null))))
                .as("a group node has no authenticator").hasSize(2);
    }

    @Test
    void aFlowWithTheStep_cannotBeBoundWithTheEngineOff() {
        when(flows.getByAlias(any())).thenReturn(new FlowDefinitionDto("acme", "stepup", false, WALLET_STEP));
        assertThatThrownBy(() -> checks(false).requireBindable("acme", "stepup", "authFlowAlias"))
                .isInstanceOf(ProviderValidationException.class);
        checks(true).requireBindable("acme", "stepup", "authFlowAlias");
        checks(false).requireBindable("acme", null, "authFlowAlias");
        when(flows.getByAlias(any())).thenReturn(new FlowDefinitionDto("acme", "plain", false,
                List.of(step("otp", null))));
        checks(false).requireBindable("acme", "plain", "authFlowAlias");
    }

    @Test
    void anApplicationsSingleSignOn_neverNamesAVerifyOnlyConnection() {
        assertThatThrownBy(() -> checks(true).requireValid("acme", List.of(step("idp-redirect",
                Map.of("providerAlias", "eudi-verify", "mode", "REDIRECT")))))
                .isInstanceOf(ProviderValidationException.class)
                .satisfies(e -> assertThat(((ProviderValidationException) e).fieldErrors())
                        .containsKey("executions[0].config.providerAlias"));
        assertThatThrownBy(() -> checks(true).requireValid("acme", List.of(step("idp-redirect",
                Map.of("providerAliases", "eudi-wallet, eudi-verify", "mode", "OPTION")))))
                .isInstanceOf(ProviderValidationException.class);
        assertThat(checks(true).requireValid("acme", List.of(step("idp-redirect",
                Map.of("providerAliases", "eudi-wallet,unknown", "mode", "OPTION"))))).hasSize(1);
    }
}
