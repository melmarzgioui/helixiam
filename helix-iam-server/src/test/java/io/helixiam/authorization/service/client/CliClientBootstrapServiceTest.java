package io.helixiam.authorization.service.client;

import io.helixiam.authorization.domain.ServiceProviderOAuthClient;
import io.helixiam.authorization.repository.ServiceProviderRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Story 4 (CLI auth #148): the built-in {@code kubedna-cli} public client is seeded into every realm so the
 * command-line tool works against any Helix deployment out of the box — a native/public app (no secret, PKCE)
 * that supports the browser authorization_code flow, refresh, and the RFC 8628 device-code flow.
 */
class CliClientBootstrapServiceTest {

    private ServiceProviderRepository repository;
    private CliClientBootstrapService service;

    @BeforeEach
    void setUp() {
        repository = mock(ServiceProviderRepository.class);
        service = new CliClientBootstrapService(repository);
    }

    @Test
    void ensureCliClient_seedsPublicPkceClient_whenAbsent() {
        when(repository.findByClientIdAndRealmIdAndDeleted("kubedna-cli", "master", false)).thenReturn(Optional.empty());
        when(repository.save(any(ServiceProviderOAuthClient.class))).thenAnswer(inv -> inv.getArgument(0));

        service.ensureCliClient("master");

        final ArgumentCaptor<ServiceProviderOAuthClient> captor = ArgumentCaptor.forClass(ServiceProviderOAuthClient.class);
        verify(repository).save(captor.capture());
        final ServiceProviderOAuthClient c = captor.getValue();

        assertEquals("kubedna-cli", c.getClientId());
        assertEquals("master", c.getRealmId(), "realmId is set explicitly (create() only sets tenantId)");
        assertEquals("master", c.getTenantId());
        assertFalse(c.getDeleted());
        assertTrue(c.getPublicClient(), "the CLI client is public — no secret, PKCE protects the code exchange");
        assertNull(c.getClientSecret(), "public clients carry no secret");
        assertTrue(c.getClientSettings().isRequireProofKey(), "PKCE is enforced for the public client");

        final List<String> grants = c.getAuthorizationGrantTypes().stream()
                .map(g -> g.getValue()).toList();
        assertTrue(grants.contains("authorization_code"), "browser login");
        assertTrue(grants.contains("refresh_token"), "silent token refresh");
        assertTrue(grants.contains("urn:ietf:params:oauth:grant-type:device_code"), "headless device login (RFC 8628)");

        assertTrue(c.getRedirectUris().stream().anyMatch(u -> u.startsWith("http://127.0.0.1")),
                "a loopback redirect URI is registered for the native-app browser flow (RFC 8252)");
        assertTrue(c.getScopes().containsAll(List.of("openid", "offline_access")),
                "standard OIDC scopes incl. offline_access so a refresh token is issued");
        assertFalse(c.getConsentRequired(), "the first-party CLI is trusted — no consent prompt");
    }

    @Test
    void ensureCliClient_isIdempotent_whenAlreadyPresent() {
        when(repository.findByClientIdAndRealmIdAndDeleted("kubedna-cli", "master", false))
                .thenReturn(Optional.of(new ServiceProviderOAuthClient()));

        service.ensureCliClient("master");

        verify(repository, never()).save(any());
    }
}
