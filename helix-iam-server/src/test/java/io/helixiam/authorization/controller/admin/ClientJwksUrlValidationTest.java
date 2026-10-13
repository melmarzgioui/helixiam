/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.controller.admin;

import io.helixiam.authorization.amqp.client.ClientAdminPublisher;
import io.helixiam.common.startup.DeploymentProfile;
import org.junit.jupiter.api.Test;
import org.springframework.http.ResponseEntity;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

/** The admin client API requires an https jwksUrl (the token endpoint fetches it); http://localhost only in dev. */
class ClientJwksUrlValidationTest {

    private static ClientRequest request(final String jwksUrl) {
        return new ClientRequest("svc", List.of("client_credentials"), null, null, null, null, null, null, null, null,
                false, null, null, null, null, null, null, null, null, null, null, null, "PRIVATE_KEY_JWT", jwksUrl,
                null, null, null, null, null, null, null);
    }

    @Test
    void anHttpJwksUrlIsRefusedInProduction() {
        final ClientAdminPublisher publisher = mock(ClientAdminPublisher.class);
        final ClientAdminController controller = new ClientAdminController(publisher, DeploymentProfile.production());
        for (final String url : List.of("http://jwks.example/keys", "http://localhost:8080/jwks", "ftp://x/keys",
                "not a url")) {
            final ResponseEntity<?> r = controller.create("acme", request(url));
            assertThat(r.getStatusCode().value()).as(url).isEqualTo(400);
            assertThat(((Map<?, ?>) ((Map<?, ?>) r.getBody()).get("fieldErrors")).containsKey("jwksUrl")).isTrue();
            assertThat(controller.update("acme", "id-1", request(url)).getStatusCode().value()).isEqualTo(400);
        }
        verify(publisher, never()).create(any());
        verify(publisher, never()).update(any());
    }

    @Test
    void httpsIsAcceptedAndLocalhostOverHttpOnlyInDev() {
        final ClientAdminPublisher publisher = mock(ClientAdminPublisher.class);
        new ClientAdminController(publisher, DeploymentProfile.production()).create("acme",
                request("https://jwks.example/keys"));
        final ClientAdminController dev = new ClientAdminController(publisher, DeploymentProfile.development());
        dev.create("acme", request("http://localhost:8080/jwks"));
        dev.create("acme", request("http://127.0.0.1:8080/jwks"));
        assertThat(dev.create("acme", request("http://jwks.example/keys")).getStatusCode().value()).isEqualTo(400);
        verify(publisher, org.mockito.Mockito.times(3)).create(any());
    }
}
