package group.mfnr.authorization.service.saml;

import group.mfnr.authorization.domain.saml.SamlRelyingPartyConfig;
import group.mfnr.authorization.domain.saml.SamlRelyingPartyEntity;
import group.mfnr.authorization.repository.saml.SamlRelyingPartyRepository;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Helix IAM: the SAML relying-party store CRUD — upsert by (realm, entityId), realm-scoped list, and
 * delete-returns-false-when-absent. Mirrors the federation IdentityProviderConfig store behaviour.
 */
class SamlRelyingPartyConfigServiceTest {

    private final SamlRelyingPartyRepository repository = mock(SamlRelyingPartyRepository.class);
    private final SamlRelyingPartyConfigService service = new SamlRelyingPartyConfigService(repository);

    private static SamlRelyingPartyConfig sampleConfig() {
        return new SamlRelyingPartyConfig("master", "helix-sandbox-sp", "http://localhost:9090/saml/acs",
                "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport",
                "http://localhost:9090/saml/slo", null, true, null, null);
    }

    @Test
    void saveOrUpdate_upsertsByRealmAndEntityId_andReturnsThePersistedState() {
        when(repository.findById("master|helix-sandbox-sp")).thenReturn(Optional.empty());
        when(repository.save(any(SamlRelyingPartyEntity.class))).thenAnswer(i -> i.getArgument(0));

        final SamlRelyingPartyConfig saved = service.saveOrUpdate(sampleConfig());

        assertThat(saved.realmId()).isEqualTo("master");
        assertThat(saved.entityId()).isEqualTo("helix-sandbox-sp");
        assertThat(saved.assertionConsumerServiceUrl()).isEqualTo("http://localhost:9090/saml/acs");
        assertThat(saved.singleLogoutServiceUrl()).isEqualTo("http://localhost:9090/saml/slo");
        assertThat(saved.enabled()).isTrue();

        // the surrogate key is realmId|entityId
        verify(repository).findById("master|helix-sandbox-sp");
    }

    @Test
    void saveOrUpdate_rejectsBlankEntityId() {
        final SamlRelyingPartyConfig config = new SamlRelyingPartyConfig("master", "  ",
                "http://localhost:9090/saml/acs", null, null, null, true, null, null);
        assertThatThrownBy(() -> service.saveOrUpdate(config))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("Entity ID is required.");
    }

    @Test
    void saveOrUpdate_rejectsBlankAcsUrl() {
        final SamlRelyingPartyConfig config = new SamlRelyingPartyConfig("master", "helix-sandbox-sp",
                "  ", null, null, null, true, null, null);
        assertThatThrownBy(() -> service.saveOrUpdate(config))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("Assertion Consumer Service URL is required.");
    }

    @Test
    void list_mapsAllEntitiesForTheRealm() {
        final SamlRelyingPartyEntity entity = new SamlRelyingPartyEntity();
        entity.setRealmId("master");
        entity.setEntityId("helix-sandbox-sp");
        entity.setAssertionConsumerServiceUrl("http://localhost:9090/saml/acs");
        entity.setEnabled(true);
        when(repository.findAllByRealmId("master")).thenReturn(List.of(entity));

        final List<SamlRelyingPartyConfig> list = service.list("master");

        assertThat(list).singleElement()
                .satisfies(c -> assertThat(c.entityId()).isEqualTo("helix-sandbox-sp"));
    }

    @Test
    void get_returnsEmptyWhenAbsent() {
        when(repository.findByRealmIdAndEntityId("master", "nope")).thenReturn(Optional.empty());
        assertThat(service.get("master", "nope")).isEmpty();
    }

    @Test
    void delete_returnsFalseWhenAbsent_andTrueWhenRemoved() {
        when(repository.existsByRealmIdAndEntityId("master", "ghost")).thenReturn(false);
        assertThat(service.delete("master", "ghost")).isFalse();

        when(repository.existsByRealmIdAndEntityId("master", "helix-sandbox-sp")).thenReturn(true);
        assertThat(service.delete("master", "helix-sandbox-sp")).isTrue();
        verify(repository).deleteByRealmIdAndEntityId("master", "helix-sandbox-sp");
    }
}
