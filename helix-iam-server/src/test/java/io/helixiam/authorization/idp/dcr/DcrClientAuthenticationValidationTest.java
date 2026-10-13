/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.idp.dcr;

import io.helixiam.authorization.amqp.client.ClientAdminPublisher;
import io.helixiam.authorization.amqp.client.ClientWriteDto;
import io.helixiam.authorization.idp.provisioning.ProvisioningAdminPublisher;
import io.helixiam.authorization.security.realm.RealmContextHolder;
import io.helixiam.common.net.OutboundUrlGuard;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.net.InetAddress;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * DCR: {@code token_endpoint_auth_method} is one of the methods the server supports, and a {@code jwks_uri} (which the
 * token endpoint fetches for private_key_jwt) must be https and pass the outbound guard at registration time.
 */
class DcrClientAuthenticationValidationTest {

    private final ClientAdminPublisher clients = mock(ClientAdminPublisher.class);
    private final ProvisioningAdminPublisher provisioning = mock(ProvisioningAdminPublisher.class);
    /** jwks.example is public; internal.example resolves to the metadata address. */
    private final OutboundUrlGuard guard = new OutboundUrlGuard(false, List.of(), host -> host.matches("[0-9.]+")
            ? new InetAddress[] {InetAddress.getByName(host)} // IP literals resolve to themselves
            : new InetAddress[] {InetAddress.getByAddress(host, host.startsWith("internal") ? new byte[] {(byte) 169,
                    (byte) 254, (byte) 169, (byte) 254} : new byte[] {93, (byte) 184, (byte) 216, 34})});
    private final DynamicClientRegistrationController controller =
            new DynamicClientRegistrationController(clients, provisioning, guard);

    @BeforeEach
    void bind() {
        RealmContextHolder.set("gov");
        final MockHttpServletRequest request = new MockHttpServletRequest();
        request.setContextPath("/realms/gov");
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));
        when(provisioning.isDcrOpen("gov")).thenReturn(true);
    }

    @AfterEach
    void clear() {
        RealmContextHolder.clear();
        RequestContextHolder.resetRequestAttributes();
    }

    private ResponseEntity<?> register(final String method, final String jwksUri) {
        return controller.register(new ClientRegistrationRequest(List.of("https://app.example/cb"),
                List.of("authorization_code"), null, method, "App", "openid", null, jwksUri, null),
                new MockHttpServletRequest());
    }

    private static String error(final ResponseEntity<?> r) {
        return ((DcrError) r.getBody()).error();
    }

    @Test
    void anUnknownAuthMethodIsRefused() {
        for (final String method : List.of("PRIVATE_KEY_JWT", "client_secret_post", "tls_client_auth", "x")) {
            final ResponseEntity<?> r = register(method, "https://jwks.example/keys");
            assertThat(r.getStatusCode()).as(method).isEqualTo(HttpStatus.BAD_REQUEST);
            assertThat(error(r)).isEqualTo("invalid_client_metadata");
        }
        verify(clients, never()).create(any());
    }

    @Test
    void privateKeyJwtNeedsAnHttpsJwksUriThatTheGuardAllows() {
        for (final String uri : new String[] {null, "http://jwks.example/keys", "https://internal.example/keys",
            "https://169.254.169.254/keys", "not a uri"}) {
            final ResponseEntity<?> r = register("private_key_jwt", uri);
            assertThat(r.getStatusCode()).as(String.valueOf(uri)).isEqualTo(HttpStatus.BAD_REQUEST);
            assertThat(error(r)).isEqualTo("invalid_client_metadata");
        }
        verify(clients, never()).create(any());
    }

    @Test
    void aValidPrivateKeyJwtRegistrationIsStoredAsTheServerKnowsIt() {
        when(clients.create(any())).thenReturn(null); // the outcome after storing does not matter here
        register("private_key_jwt", "https://jwks.example/keys");
        final ArgumentCaptor<ClientWriteDto> captor = ArgumentCaptor.forClass(ClientWriteDto.class);
        verify(clients).create(captor.capture());
        assertThat(captor.getValue().tokenEndpointAuthMethod()).isEqualTo("PRIVATE_KEY_JWT");
        assertThat(captor.getValue().jwksUrl()).isEqualTo("https://jwks.example/keys");
    }
}
