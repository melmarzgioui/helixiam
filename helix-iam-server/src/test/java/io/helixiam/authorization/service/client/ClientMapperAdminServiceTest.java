package io.helixiam.authorization.service.client;

import io.helixiam.authorization.domain.client.mapper.ClientProtocolMapperEntity;
import io.helixiam.authorization.domain.client.mapper.ProtocolMapperDto;
import io.helixiam.authorization.domain.client.mapper.ProtocolMapperWriteDto;
import io.helixiam.authorization.repository.ClientProtocolMapperRepository;
import io.helixiam.authorization.repository.ServiceProviderRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Helix IAM (Wave 3): per-client protocol mapper administration over the {@code client_protocol_mapper} store.
 */
class ClientMapperAdminServiceTest {

    private ClientProtocolMapperRepository repository;
    private ServiceProviderRepository clients;
    private ClientMapperAdminService service;

    @BeforeEach
    void setUp() {
        repository = mock(ClientProtocolMapperRepository.class);
        clients = mock(ServiceProviderRepository.class);
        service = new ClientMapperAdminService(repository, clients);
    }

    private static ClientProtocolMapperEntity entity(final String id, final String name) {
        final ClientProtocolMapperEntity e = new ClientProtocolMapperEntity();
        e.setMapperId(id);
        e.setRealmId("gov");
        e.setClientId("portal");
        e.setName(name);
        e.setMapperType("USER_ATTRIBUTE");
        e.setSource("department");
        e.setClaimName("dept");
        e.setAddToAccessToken(true);
        e.setAddToIdToken(false);
        return e;
    }

    @Test
    void create_persistsTheMapper_andReturnsItWithGeneratedId() {
        when(repository.save(any(ClientProtocolMapperEntity.class))).thenAnswer(inv -> inv.getArgument(0));

        final ProtocolMapperDto dto = service.create(new ProtocolMapperWriteDto(null, "gov", "portal",
                "Department", "USER_ATTRIBUTE", "department", "dept", true, false));

        final ArgumentCaptor<ClientProtocolMapperEntity> captor = ArgumentCaptor.forClass(ClientProtocolMapperEntity.class);
        verify(repository).save(captor.capture());
        final ClientProtocolMapperEntity saved = captor.getValue();
        assertEquals("portal", saved.getClientId());
        assertEquals("gov", saved.getRealmId());
        assertEquals("USER_ATTRIBUTE", saved.getMapperType());
        assertEquals("department", saved.getSource());
        assertEquals("dept", saved.getClaimName());
        assertTrue(saved.getAddToAccessToken());
        assertFalse(saved.getAddToIdToken());
        assertEquals("Department", dto.name());
    }

    @Test
    void list_returnsTheClientsMappers() {
        when(repository.findAllByRealmIdAndClientIdOrderByName("gov", "portal"))
                .thenReturn(List.of(entity("m-1", "Department")));
        final List<ProtocolMapperDto> out = service.list("gov", "portal");
        assertEquals(1, out.size());
        assertEquals("dept", out.get(0).claimName());
    }

    @Test
    void update_changesFields_whenTheMapperBelongsToTheClient() {
        when(repository.findByMapperIdAndRealmIdAndClientId("m-1", "gov", "portal"))
                .thenReturn(Optional.of(entity("m-1", "Department")));
        when(repository.save(any(ClientProtocolMapperEntity.class))).thenAnswer(inv -> inv.getArgument(0));

        final Optional<ProtocolMapperDto> out = service.update(new ProtocolMapperWriteDto("m-1", "gov", "portal",
                "Cost centre", "HARDCODED", "cc-42", "cost_centre", false, true));

        assertTrue(out.isPresent());
        assertEquals("HARDCODED", out.get().mapperType());
        assertEquals("cost_centre", out.get().claimName());
        assertFalse(out.get().addToAccessToken());
        assertTrue(out.get().addToIdToken());
    }

    @Test
    void delete_returnsFalse_whenAbsent() {
        when(repository.findByMapperIdAndRealmIdAndClientId("nope", "gov", "portal")).thenReturn(Optional.empty());
        assertFalse(service.delete("gov", "portal", "nope"));
    }

    @Test
    void mappersForClient_resolvesTheClientsRealm_thenItsMappers() {
        final io.helixiam.authorization.domain.ServiceProviderOAuthClient c =
                new io.helixiam.authorization.domain.ServiceProviderOAuthClient();
        c.setClientId("portal");
        c.setTenantId("gov");
        when(clients.findByClientIdAndRealmIdAndDeleted("portal", "gov", false)).thenReturn(Optional.of(c));
        when(repository.findAllByRealmIdAndClientIdOrderByName("gov", "portal"))
                .thenReturn(List.of(entity("m-1", "Department")));

        final List<ProtocolMapperDto> out = service.mappersForClient("gov", "portal");
        assertEquals(1, out.size());
        assertEquals("dept", out.get(0).claimName());
    }
}
