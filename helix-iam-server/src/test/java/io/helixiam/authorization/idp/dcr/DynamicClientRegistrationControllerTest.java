/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.idp.dcr;

import io.helixiam.authorization.amqp.client.ClientAdminPublisher;
import io.helixiam.authorization.amqp.client.ClientDto;
import io.helixiam.authorization.amqp.client.ClientWriteDto;
import io.helixiam.authorization.idp.provisioning.DcrBindRequest;
import io.helixiam.authorization.idp.provisioning.DcrRegistrationDto;
import io.helixiam.authorization.idp.provisioning.ProvisioningAdminPublisher;
import io.helixiam.authorization.idp.provisioning.ScimTokenCheck;
import io.helixiam.authorization.security.realm.RealmContextHolder;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Helix IAM E11 (RFC 7591/7592): Dynamic Client Registration — register returns the issued credentials +
 * RFC 7592 management token, and the GATED policy (default) rejects an anonymous registration that
 * presents no initial access token. Never-throw contract: all responses are {@link ResponseEntity}.
 */
class DynamicClientRegistrationControllerTest {

    private final ClientAdminPublisher clients = mock(ClientAdminPublisher.class);
    private final ProvisioningAdminPublisher provisioning = mock(ProvisioningAdminPublisher.class);
    private final DynamicClientRegistrationController controller =
            new DynamicClientRegistrationController(clients, provisioning);

    @BeforeEach
    void bindRealm() {
        RealmContextHolder.set("gov");
    }

    @AfterEach
    void clear() {
        RealmContextHolder.clear();
        RequestContextHolder.resetRequestAttributes();
    }

    private MockHttpServletRequest request(final String bearer) {
        final MockHttpServletRequest request = new MockHttpServletRequest();
        request.setContextPath("/realms/gov");
        if (bearer != null) {
            request.addHeader("Authorization", "Bearer " + bearer);
        }
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));
        return request;
    }

    private ClientRegistrationRequest validRequest() {
        return new ClientRegistrationRequest(List.of("https://app.example/cb"), List.of("authorization_code"),
                null, "client_secret_basic", "My App", "openid profile", null, null, null);
    }

    @Test
    void gatedMode_rejectsWithoutInitialAccessToken_401_andDoesNotCreateAClient() {
        when(provisioning.isDcrOpen("gov")).thenReturn(false);

        final ResponseEntity<?> response = controller.register(validRequest(), request(null));

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(response.getBody()).isInstanceOf(DcrError.class);
        assertThat(((DcrError) response.getBody()).error()).isEqualTo("invalid_token");
        verify(clients, never()).create(any());
    }

    @Test
    void gatedMode_rejectsInvalidInitialAccessToken_401() {
        when(provisioning.isDcrOpen("gov")).thenReturn(false);
        when(provisioning.consumeInitialAccessToken(new ScimTokenCheck("gov", "bad"))).thenReturn(false);

        final ResponseEntity<?> response = controller.register(validRequest(), request("bad"));

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        verify(clients, never()).create(any());
    }

    @Test
    void register_returnsCredentialsAndManagementToken() {
        when(provisioning.isDcrOpen("gov")).thenReturn(false);
        when(provisioning.consumeInitialAccessToken(new ScimTokenCheck("gov", "iat"))).thenReturn(true);
        when(clients.create(any())).thenReturn(stored("internal-1", "dcr-abc", "s3cr3t"));
        when(provisioning.bind(any(DcrBindRequest.class)))
                .thenReturn(new DcrRegistrationDto("reg-1", "gov", "internal-1", "dcr-abc", "rat-xyz"));

        final ResponseEntity<?> response = controller.register(validRequest(), request("iat"));

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.CREATED);
        final ClientRegistrationResponse body = (ClientRegistrationResponse) response.getBody();
        assertThat(body.clientId()).isEqualTo("dcr-abc");
        assertThat(body.clientSecret()).isEqualTo("s3cr3t");
        assertThat(body.registrationAccessToken()).isEqualTo("rat-xyz");
        assertThat(body.registrationClientUri()).endsWith("/connect/register/internal-1");

        final var captor = org.mockito.ArgumentCaptor.forClass(ClientWriteDto.class);
        verify(clients).create(captor.capture());
        assertThat(captor.getValue().redirectUris()).containsExactly("https://app.example/cb");
        assertThat(captor.getValue().grantTypes()).containsExactly("authorization_code");
    }

    @Test
    void openMode_registersWithoutAnyToken() {
        when(provisioning.isDcrOpen("gov")).thenReturn(true);
        when(clients.create(any())).thenReturn(stored("internal-2", "dcr-open", "sec"));
        when(provisioning.bind(any(DcrBindRequest.class)))
                .thenReturn(new DcrRegistrationDto("reg-2", "gov", "internal-2", "dcr-open", "rat-2"));

        final ResponseEntity<?> response = controller.register(validRequest(), request(null));

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.CREATED);
        verify(provisioning, never()).consumeInitialAccessToken(any());
        verify(clients).create(any());
    }

    @Test
    void register_rejectsMissingRedirectUriForAuthCode_400() {
        when(provisioning.isDcrOpen("gov")).thenReturn(true);
        final ClientRegistrationRequest noRedirect = new ClientRegistrationRequest(null,
                List.of("authorization_code"), null, "client_secret_basic", "App", null, null, null, null);

        final ResponseEntity<?> response = controller.register(noRedirect, request(null));

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(((DcrError) response.getBody()).error()).isEqualTo("invalid_redirect_uri");
        verify(clients, never()).create(any());
    }

    private static ClientDto stored(final String internalId, final String clientId, final String secret) {
        return new ClientDto("gov", internalId, clientId, List.of("authorization_code"),
                List.of("https://app.example/cb"), List.of("openid", "profile"), secret, null, null, "My App", null,
                List.of(), List.of(), false, null, null, null, null, null, null, false, null, null, null, false,
                "client_secret_basic", null, null, null, null, null, null, null);
    }
}
