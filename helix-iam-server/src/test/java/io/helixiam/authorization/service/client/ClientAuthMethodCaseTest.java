/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.service.client;

import io.helixiam.authorization.amqp.client.ClientAdminPublisher;
import io.helixiam.authorization.controller.admin.ClientAdminController;
import io.helixiam.authorization.controller.admin.ClientRequest;
import io.helixiam.authorization.domain.ServiceProviderOAuthClient;
import io.helixiam.authorization.domain.client.admin.ClientWriteDto;
import io.helixiam.authorization.repository.ServiceProviderRepository;
import io.helixiam.common.startup.DeploymentProfile;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * The token endpoint auth method is matched case-insensitively and stored in one spelling; an unknown spelling is
 * refused, never silently treated as client_secret_basic.
 */
class ClientAuthMethodCaseTest {

    @Test
    void knownSpellingsAreNormalisedAndUnknownOnesRefused() {
        assertThat(ClientAuthMethods.normalize("private_key_jwt")).isEqualTo("PRIVATE_KEY_JWT");
        assertThat(ClientAuthMethods.normalize("Private_Key_JWT")).isEqualTo("PRIVATE_KEY_JWT");
        assertThat(ClientAuthMethods.normalize(" PRIVATE_KEY_JWT ")).isEqualTo("PRIVATE_KEY_JWT");
        assertThat(ClientAuthMethods.normalize("CLIENT_SECRET_BASIC")).isEqualTo("client_secret_basic");
        assertThat(ClientAuthMethods.normalize("None")).isEqualTo("none");
        assertThat(ClientAuthMethods.normalize(null)).isNull();
        assertThat(ClientAuthMethods.normalize(" ")).isNull();
        for (final String bad : List.of("private-key-jwt", "privatekeyjwt", "client_secret_jwt", "tls_client_auth",
                "x")) {
            assertThat(ClientAuthMethods.problem(bad)).as(bad).isNotNull();
            assertThatThrownBy(() -> ClientAuthMethods.normalize(bad)).isInstanceOf(IllegalArgumentException.class);
        }
        assertThat(ClientAuthMethods.problem("private_key_jwt")).isNull();
    }

    @Test
    void aLowercaseStoredMethodStillMeansPrivateKeyJwt() {
        final ServiceProviderOAuthClient client = new ServiceProviderOAuthClient();
        client.setTokenEndpointAuthMethod("private_key_jwt");
        client.setJwksUrl("https://keys.example.com/jwks");
        assertThat(client.getClientAuthenticationMethods())
                .containsExactly(ClientAuthenticationMethod.PRIVATE_KEY_JWT);
    }

    @Test
    void theServiceStoresTheCanonicalSpelling() {
        final ServiceProviderRepository repo = mock(ServiceProviderRepository.class);
        when(repo.existsByClientIdAndDeleted("svc", false)).thenReturn(false);
        when(repo.save(any(ServiceProviderOAuthClient.class))).thenAnswer(inv -> inv.getArgument(0));
        new ClientAdminService(repo).create(new ClientWriteDto("gov", null, "svc", List.of("client_credentials"),
                List.of(), List.of(), null, null, null, null, List.of(), List.of(), false, false, true, null, null,
                null, null, false, null, null, null, false, "Private_Key_Jwt", "https://keys.example.com/jwks", null,
                null, null, null, null, null, null));
        final ArgumentCaptor<ServiceProviderOAuthClient> saved = ArgumentCaptor.forClass(ServiceProviderOAuthClient.class);
        verify(repo).save(saved.capture());
        assertThat(saved.getValue().getTokenEndpointAuthMethod()).isEqualTo("PRIVATE_KEY_JWT");
    }

    @Test
    void theAdminApiRefusesAnUnknownSpellingWithAFieldError() {
        final ClientAdminPublisher publisher = mock(ClientAdminPublisher.class);
        final ClientAdminController controller = new ClientAdminController(publisher, DeploymentProfile.production());
        final ResponseEntity<?> r = controller.create("acme", new ClientRequest("svc", List.of("client_credentials"),
                null, null, null, null, null, null, null, null, false, null, null, null, null, null, null, null, null,
                null, null, null, "private-key-jwt", "https://keys.example.com/jwks", null, null, null, null, null,
                null, null));
        assertThat(r.getStatusCode().value()).isEqualTo(400);
        assertThat(((Map<?, ?>) ((Map<?, ?>) r.getBody()).get("fieldErrors")).containsKey("tokenEndpointAuthMethod"))
                .isTrue();
        verify(publisher, never()).create(any());
    }
}
