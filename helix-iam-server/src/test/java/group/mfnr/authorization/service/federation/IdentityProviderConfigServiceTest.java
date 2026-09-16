package group.mfnr.authorization.service.federation;

import group.mfnr.authorization.domain.federation.IdentityProviderConfig;
import group.mfnr.authorization.domain.federation.IdentityProviderEntity;
import group.mfnr.authorization.repository.federation.IdentityProviderConfigRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Helix IAM E8.1: persistence service for per-realm identity-provider configs.
 */
class IdentityProviderConfigServiceTest {

    private IdentityProviderConfigRepository repository;
    private IdentityProviderConfigService service;

    @BeforeEach
    void setUp() {
        repository = mock(IdentityProviderConfigRepository.class);
        service = new IdentityProviderConfigService(repository);
    }

    @Test
    void saveOrUpdate_persistsEntityKeyedByRealmAndAlias_withConfigSerialised() {
        when(repository.save(any(IdentityProviderEntity.class))).thenAnswer(inv -> inv.getArgument(0));

        final IdentityProviderConfig cfg = new IdentityProviderConfig(
                "gov", "digid", "saml", "DigiD (CombiConnect)", true,
                Map.of("ssoUrl", "https://digid.example/sso", "spEntityId", "https://helix.example/sp"));

        final IdentityProviderConfig saved = service.saveOrUpdate(cfg);

        final ArgumentCaptor<IdentityProviderEntity> captor = ArgumentCaptor.forClass(IdentityProviderEntity.class);
        verify(repository).save(captor.capture());
        final IdentityProviderEntity entity = captor.getValue();
        assertEquals("gov|digid", entity.getId());
        assertEquals("gov", entity.getRealmId());
        assertEquals("digid", entity.getAlias());
        assertEquals("saml", entity.getProtocol());
        assertTrue(entity.getConfigJson().contains("ssoUrl"), "config map should be serialised to JSON");

        assertEquals("digid", saved.alias());
        assertEquals("https://digid.example/sso", saved.config().get("ssoUrl"));
    }

    @Test
    void list_returnsConfigsForRealm_withConfigDeserialised() {
        when(repository.findAllByRealmId("gov"))
                .thenReturn(List.of(entity("gov", "digid", "saml", "DigiD", true, "{\"ssoUrl\":\"https://idp\"}")));

        final List<IdentityProviderConfig> list = service.list("gov");

        assertEquals(1, list.size());
        assertEquals("digid", list.get(0).alias());
        assertEquals("https://idp", list.get(0).config().get("ssoUrl"));
    }

    @Test
    void get_returnsConfig_whenPresent_andEmpty_whenAbsent() {
        when(repository.findByRealmIdAndAlias("gov", "digid"))
                .thenReturn(Optional.of(entity("gov", "digid", "saml", "DigiD", true, "{}")));
        when(repository.findByRealmIdAndAlias("gov", "ghost")).thenReturn(Optional.empty());

        assertTrue(service.get("gov", "digid").isPresent());
        assertTrue(service.get("gov", "ghost").isEmpty());
    }

    @Test
    void delete_removes_whenPresent_andReturnsFalse_whenAbsent() {
        when(repository.existsByRealmIdAndAlias("gov", "digid")).thenReturn(true);
        when(repository.existsByRealmIdAndAlias("gov", "ghost")).thenReturn(false);

        assertTrue(service.delete("gov", "digid"));
        verify(repository).deleteByRealmIdAndAlias("gov", "digid");

        assertFalse(service.delete("gov", "ghost"));
        verify(repository, never()).deleteByRealmIdAndAlias("gov", "ghost");
    }

    private static IdentityProviderEntity entity(final String realm, final String alias, final String protocol,
                                                 final String displayName, final boolean enabled, final String json) {
        final IdentityProviderEntity e = new IdentityProviderEntity();
        e.setId(IdentityProviderEntity.key(realm, alias));
        e.setRealmId(realm);
        e.setAlias(alias);
        e.setProtocol(protocol);
        e.setDisplayName(displayName);
        e.setEnabled(enabled);
        e.setConfigJson(json);
        return e;
    }
}
