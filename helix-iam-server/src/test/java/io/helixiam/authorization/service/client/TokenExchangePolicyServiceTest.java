/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.service.client;

import io.helixiam.authorization.domain.ServiceProviderOAuthClient;
import io.helixiam.authorization.repository.ServiceProviderRepository;
import org.junit.jupiter.api.Test;

import java.util.Optional;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/** 1.0 item 5: the token-exchange target policy decision. */
class TokenExchangePolicyServiceTest {

    private final ServiceProviderRepository repository = mock(ServiceProviderRepository.class);
    private final TokenExchangePolicyService service = new TokenExchangePolicyService(repository);

    @Test
    void decide_unknownTarget_notAllowed_allowed() {
        final ServiceProviderOAuthClient ledger = new ServiceProviderOAuthClient();
        ledger.setClientId("ledger");
        ledger.setTokenExchangeAllowedClients("web, backoffice");
        when(repository.findByClientIdAndRealmIdAndDeleted("ledger", "monthfold", false)).thenReturn(Optional.of(ledger));
        when(repository.findByClientIdAndRealmIdAndDeleted("nope", "monthfold", false)).thenReturn(Optional.empty());

        assertThat(service.decide("monthfold", "web", "ledger")).isEqualTo(TokenExchangePolicyService.Decision.ALLOWED);
        assertThat(service.decide("monthfold", "backoffice", "ledger")).isEqualTo(TokenExchangePolicyService.Decision.ALLOWED);
        assertThat(service.decide("monthfold", "portal", "ledger")).isEqualTo(TokenExchangePolicyService.Decision.NOT_ALLOWED);
        assertThat(service.decide("monthfold", "web", "nope")).isEqualTo(TokenExchangePolicyService.Decision.UNKNOWN_TARGET);
        assertThat(service.decide("other-realm", "web", "ledger")).isEqualTo(TokenExchangePolicyService.Decision.UNKNOWN_TARGET);
    }

    @Test
    void emptyPolicy_allowsNobody() {
        final ServiceProviderOAuthClient ledger = new ServiceProviderOAuthClient();
        ledger.setClientId("ledger");
        when(repository.findByClientIdAndRealmIdAndDeleted("ledger", "monthfold", false)).thenReturn(Optional.of(ledger));

        assertThat(service.allowedClients("monthfold", "ledger")).contains(Set.of());
        assertThat(service.decide("monthfold", "web", "ledger")).isEqualTo(TokenExchangePolicyService.Decision.NOT_ALLOWED);
    }
}
