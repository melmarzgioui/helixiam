/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.service.client;

import io.helixiam.authorization.domain.ServiceProviderOAuthClient;
import io.helixiam.authorization.repository.ServiceProviderRepository;
import io.helixiam.testsupport.LogCapture;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/** private_key_jwt clients without a JWKS URL are flagged at startup. */
class ClientAuthMethodAuditTest {

    @Test
    void clientsThatCannotAuthenticateWithAKeyAreLogged() {
        final ServiceProviderRepository repo = Mockito.mock(ServiceProviderRepository.class);
        final ServiceProviderOAuthClient c = new ServiceProviderOAuthClient();
        c.setClientId("dcr-b");
        Mockito.when(repo.findPrivateKeyJwtWithoutJwksUrl()).thenReturn(List.of(c));
        try (LogCapture log = LogCapture.of(ClientAuthMethodAudit.class)) {
            assertThat(new ClientAuthMethodAudit(repo).check()).isEqualTo(1);
            assertThat(log.text()).contains("dcr-b").contains("no JWKS URL");
        }
    }
}
