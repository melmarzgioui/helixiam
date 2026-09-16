package group.mfnr.authorization.service.client;

import group.mfnr.authorization.domain.ServiceProviderOAuthClient;
import group.mfnr.authorization.domain.client.admin.ClientDto;
import group.mfnr.authorization.domain.client.admin.ClientWriteDto;
import group.mfnr.authorization.repository.ServiceProviderRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Helix IAM E8.5-S3: OAuth client administration over the service-provider store.
 */
class ClientAdminServiceTest {

    private ServiceProviderRepository repository;
    private ClientAdminService service;

    @BeforeEach
    void setUp() {
        repository = mock(ServiceProviderRepository.class);
        service = new ClientAdminService(repository);
    }

    @Test
    void create_buildsClient_withGrantsRedirectsScopes_andGeneratesSecret() {
        when(repository.existsByClientIdAndDeleted("portal", false)).thenReturn(false);
        when(repository.save(any(ServiceProviderOAuthClient.class))).thenAnswer(inv -> inv.getArgument(0));

        final ClientDto dto = service.create(new ClientWriteDto("gov", null, "portal",
                List.of("authorization_code", "refresh_token"), List.of("https://portal/cb"), List.of("openid", "profile"),
                null, null, null, null, List.of(), List.of(),
                false, false, true, null, null, null, null, false, null, null, null, false, null, null, null, null, null, null, null, null));

        final ArgumentCaptor<ServiceProviderOAuthClient> captor = ArgumentCaptor.forClass(ServiceProviderOAuthClient.class);
        verify(repository).save(captor.capture());
        final ServiceProviderOAuthClient saved = captor.getValue();
        assertEquals("portal", saved.getClientId());
        assertEquals("gov", saved.getTenantId());
        assertFalse(saved.getDeleted());
        assertTrue(saved.getRedirectUris().contains("https://portal/cb"));
        assertTrue(saved.getScopes().containsAll(List.of("openid", "profile")));
        assertTrue(saved.getAuthorizationGrantTypes().stream().anyMatch(g -> g.getValue().equals("authorization_code")));

        // the generated secret is returned once, on create
        assertEquals("portal", dto.clientId());
        assertTrue(dto.secret() != null && !dto.secret().isBlank(), "a secret is generated and returned on create");
    }

    @Test
    void create_rejectsBlankClientId() {
        final ClientWriteDto write = new ClientWriteDto("gov", null, "  ",
                List.of("authorization_code"), List.of("https://portal/cb"), List.of("openid"),
                null, null, null, null, List.of(), List.of(),
                false, false, true, null, null, null, null, false, null, null, null, false, null, null, null, null, null, null, null, null);
        final IllegalArgumentException ex = assertThrows(IllegalArgumentException.class, () -> service.create(write));
        assertEquals("Client ID is required.", ex.getMessage());
        verify(repository, never()).save(any());
    }

    @Test
    void list_returnsRealmClients_withoutSecret() {
        when(repository.findAllByTenantIdAndDeleted("gov", false)).thenReturn(List.of(client("c-1", "portal", "gov")));
        final List<ClientDto> clients = service.list("gov");
        assertEquals(1, clients.size());
        assertEquals("portal", clients.get(0).clientId());
        assertNull(clients.get(0).secret(), "the list never exposes secrets");
    }

    @Test
    void delete_softDeletes_whenPresent_andFalse_whenAbsent() {
        final ServiceProviderOAuthClient client = client("c-1", "portal", "gov");
        when(repository.findByIdAndDeleted("c-1", false)).thenReturn(Optional.of(client));
        when(repository.findByIdAndDeleted("ghost", false)).thenReturn(Optional.empty());

        assertTrue(service.delete("gov", "c-1"));
        assertTrue(client.getDeleted());
        verify(repository).save(client);

        assertFalse(service.delete("gov", "ghost"));
    }

    @Test
    void delete_refusesProtectedConsoleClient() {
        final ServiceProviderOAuthClient console = client("c-2", ConsoleClientBootstrapService.CONSOLE_CLIENT_ID, "master");
        when(repository.findByIdAndDeleted("c-2", false)).thenReturn(Optional.of(console));

        assertFalse(service.delete("master", "c-2"));
        assertFalse(console.getDeleted());
        verify(repository, never()).save(any());
    }

    @Test
    void delete_refusesProtectedCliClient() {
        final ServiceProviderOAuthClient cli = client("c-3", CliClientBootstrapService.CLI_CLIENT_ID, "master");
        when(repository.findByIdAndDeleted("c-3", false)).thenReturn(Optional.of(cli));

        assertFalse(service.delete("master", "c-3"));
        assertFalse(cli.getDeleted());
        verify(repository, never()).save(any());
    }

    private static ServiceProviderOAuthClient client(final String id, final String clientId, final String tenantId) {
        final ServiceProviderOAuthClient c = new ServiceProviderOAuthClient();
        c.setServiceProviderId(id);
        c.setClientId(clientId);
        c.setTenantId(tenantId);
        c.setDeleted(false);
        c.setAuthorizationGrantTypes("client_credentials");
        c.setScopes("openid");
        return c;
    }
}
