package io.helixiam.authorization.service.application;

import io.helixiam.authorization.domain.ServiceProviderOAuthClient;
import io.helixiam.authorization.domain.application.ApplicationConfig;
import io.helixiam.authorization.domain.application.ApplicationEntity;
import io.helixiam.authorization.domain.saml.SamlRelyingPartyEntity;
import io.helixiam.authorization.repository.ServiceProviderRepository;
import io.helixiam.authorization.repository.application.ApplicationRepository;
import io.helixiam.authorization.repository.saml.SamlRelyingPartyRepository;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Helix IAM: the Application store CRUD — upsert by (realm, name), realm-scoped list, delete-returns-
 * false-when-absent. Mirrors the SAML relying-party + federation config store behaviour.
 */
class ApplicationConfigServiceTest {

    private final ApplicationRepository repository = mock(ApplicationRepository.class);
    private final ServiceProviderRepository serviceProviders = mock(ServiceProviderRepository.class);
    private final SamlRelyingPartyRepository relyingParties = mock(SamlRelyingPartyRepository.class);
    private final ApplicationConfigService service =
            new ApplicationConfigService(repository, serviceProviders, relyingParties);

    private static ApplicationConfig sample() {
        return new ApplicationConfig("master", "gov-portal", "The citizen portal", "email", "sandbox-otp", true, "Gov Portal");
    }

    @Test
    void saveOrUpdate_upsertsByRealmAndName_andReturnsThePersistedState() {
        when(repository.findById("master|gov-portal")).thenReturn(Optional.empty());
        when(repository.save(any(ApplicationEntity.class))).thenAnswer(i -> i.getArgument(0));

        final ApplicationConfig saved = service.saveOrUpdate(sample());

        assertThat(saved.realmId()).isEqualTo("master");
        assertThat(saved.name()).isEqualTo("gov-portal");
        assertThat(saved.displayName()).isEqualTo("Gov Portal");
        assertThat(saved.subjectClaim()).isEqualTo("email");
        assertThat(saved.authFlowAlias()).isEqualTo("sandbox-otp");
        assertThat(saved.enabled()).isTrue();
        verify(repository).findById("master|gov-portal");
    }

    @Test
    void saveOrUpdate_rejectsBlankName() {
        final ApplicationConfig config = new ApplicationConfig("master", "  ", "desc", "email", null, true, "Display");
        assertThatThrownBy(() -> service.saveOrUpdate(config))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("Application name is required.");
    }

    @Test
    void list_mapsAllEntitiesForTheRealm() {
        final ApplicationEntity e = new ApplicationEntity();
        e.setRealmId("master");
        e.setName("gov-portal");
        e.setEnabled(true);
        when(repository.findAllByRealmId("master")).thenReturn(List.of(e));

        assertThat(service.list("master")).singleElement()
                .satisfies(c -> assertThat(c.name()).isEqualTo("gov-portal"));
    }

    @Test
    void get_returnsEmptyWhenAbsent() {
        when(repository.findByRealmIdAndName("master", "nope")).thenReturn(Optional.empty());
        assertThat(service.get("master", "nope")).isEmpty();
    }

    @Test
    void delete_returnsFalseWhenAbsent_andTrueWhenRemoved() {
        when(repository.existsByRealmIdAndName("master", "ghost")).thenReturn(false);
        assertThat(service.delete("master", "ghost")).isFalse();

        when(repository.existsByRealmIdAndName("master", "gov-portal")).thenReturn(true);
        assertThat(service.delete("master", "gov-portal")).isTrue();
        verify(repository).deleteByRealmIdAndName("master", "gov-portal");
    }

    @Test
    void delete_cascadesToTheLinkedOidcClientAndSamlRelyingParty() {
        final String appId = ApplicationEntity.key("master", "gov-portal");
        when(repository.existsByRealmIdAndName("master", "gov-portal")).thenReturn(true);

        final ServiceProviderOAuthClient client = new ServiceProviderOAuthClient();
        client.setApplicationId(appId);
        when(serviceProviders.findAllByApplicationIdAndDeleted(appId, false)).thenReturn(List.of(client));
        final SamlRelyingPartyEntity rp = new SamlRelyingPartyEntity();
        rp.setApplicationId(appId);
        when(relyingParties.findAllByApplicationId(appId)).thenReturn(List.of(rp));

        assertThat(service.delete("master", "gov-portal")).isTrue();

        // OIDC client is soft-deleted (the SAS hot path filters deleted=true), SAML RP hard-deleted.
        assertThat(client.getDeleted()).isTrue();
        verify(serviceProviders).save(client);
        verify(relyingParties).delete(rp);
        verify(repository).deleteByRealmIdAndName("master", "gov-portal");
    }

    @Test
    void delete_withNoChildren_doesNotTouchTheChildRepos() {
        final String appId = ApplicationEntity.key("master", "solo");
        when(repository.existsByRealmIdAndName("master", "solo")).thenReturn(true);
        when(serviceProviders.findAllByApplicationIdAndDeleted(appId, false)).thenReturn(List.of());
        when(relyingParties.findAllByApplicationId(appId)).thenReturn(List.of());

        assertThat(service.delete("master", "solo")).isTrue();

        verify(serviceProviders, never()).save(any());
        verify(relyingParties, never()).delete(any());
    }
}
