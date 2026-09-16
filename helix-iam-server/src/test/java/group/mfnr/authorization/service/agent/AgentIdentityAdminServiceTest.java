package group.mfnr.authorization.service.agent;

import group.mfnr.authorization.domain.agent.AgentIdentity;
import group.mfnr.authorization.domain.agent.AgentIdentityDto;
import group.mfnr.authorization.repository.agent.AgentIdentityRepository;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Helix IAM Agent (NHI): registry CRUD over {@link AgentIdentity} plus the status lifecycle the console
 * drives — create defaults (status ACTIVE, auth SECRET, enabled true), realm-scoped listing/get/delete,
 * the suspend/activate/revoke transitions, and the unique-name-per-realm guard on create.
 */
class AgentIdentityAdminServiceTest {

    private final AgentIdentityRepository repo = mock(AgentIdentityRepository.class);
    private final AgentIdentityAdminService service = new AgentIdentityAdminService(repo);

    private AgentIdentityDto dto(final String id, final String name) {
        return new AgentIdentityDto(id, "master", name, "Billing Agent", "Reconciles invoices",
                "alice@example.com", null, null, "billing-service", "billing.read", true, null, null, null, null);
    }

    private AgentIdentity entity(final String id, final String realmId, final String name, final String status) {
        final AgentIdentity a = new AgentIdentity();
        a.setId(id);
        a.setRealmId(realmId);
        a.setName(name);
        a.setOwner("alice@example.com");
        a.setStatus(status);
        a.setAuthMethod("SECRET");
        a.setEnabled(true);
        return a;
    }

    @Test
    void save_appliesDefaults_andAssignsId() {
        when(repo.findByRealmIdAndName(eq("master"), eq("invoices-bot"))).thenReturn(Optional.empty());
        when(repo.save(any(AgentIdentity.class))).thenAnswer(i -> i.getArgument(0));

        final AgentIdentityDto saved = service.save(dto(null, "invoices-bot"));

        final ArgumentCaptor<AgentIdentity> c = ArgumentCaptor.forClass(AgentIdentity.class);
        verify(repo).save(c.capture());
        assertThat(c.getValue().getId()).isNotBlank();
        assertThat(c.getValue().getStatus()).isEqualTo("ACTIVE");
        assertThat(c.getValue().getAuthMethod()).isEqualTo("SECRET");
        assertThat(c.getValue().isEnabled()).isTrue();
        assertThat(saved.name()).isEqualTo("invoices-bot");
    }

    @Test
    void save_rejectsADuplicateNameInTheSameRealm() {
        when(repo.findByRealmIdAndName(eq("master"), eq("invoices-bot")))
                .thenReturn(Optional.of(entity("other", "master", "invoices-bot", "ACTIVE")));

        assertThatThrownBy(() -> service.save(dto(null, "invoices-bot")))
                .isInstanceOf(IllegalArgumentException.class);
        verify(repo, never()).save(any());
    }

    @Test
    void save_allowsRenameKeepingItsOwnName_onUpdate() {
        final AgentIdentity existing = entity("a1", "master", "invoices-bot", "ACTIVE");
        when(repo.findById("a1")).thenReturn(Optional.of(existing));
        when(repo.findByRealmIdAndName(eq("master"), eq("invoices-bot")))
                .thenReturn(Optional.of(existing));
        when(repo.save(any(AgentIdentity.class))).thenAnswer(i -> i.getArgument(0));

        service.save(dto("a1", "invoices-bot"));

        verify(repo).save(any(AgentIdentity.class));
    }

    @Test
    void list_filtersByRealm() {
        when(repo.findAllByRealmIdOrderByCreatedAtAsc("master"))
                .thenReturn(List.of(entity("a1", "master", "bot", "ACTIVE")));

        final List<AgentIdentityDto> out = service.list("master");

        assertThat(out).hasSize(1);
        assertThat(out.get(0).realmId()).isEqualTo("master");
    }

    @Test
    void get_isNullAcrossRealms() {
        final AgentIdentity other = entity("a1", "other-realm", "bot", "ACTIVE");
        when(repo.findById("a1")).thenReturn(Optional.of(other));

        assertThat(service.get("master", "a1")).isNull();
    }

    @Test
    void delete_isNoOpAcrossRealms() {
        final AgentIdentity other = entity("a1", "other-realm", "bot", "ACTIVE");
        when(repo.findById("a1")).thenReturn(Optional.of(other));

        final boolean removed = service.delete("master", "a1");

        assertThat(removed).isFalse();
        verify(repo, never()).delete(any());
    }

    @Test
    void suspend_setsStatusSuspended() {
        when(repo.findById("a1")).thenReturn(Optional.of(entity("a1", "master", "bot", "ACTIVE")));
        when(repo.save(any(AgentIdentity.class))).thenAnswer(i -> i.getArgument(0));

        final AgentIdentityDto out = service.suspend("master", "a1");

        assertThat(out.status()).isEqualTo("SUSPENDED");
    }

    @Test
    void activate_setsStatusActive() {
        when(repo.findById("a1")).thenReturn(Optional.of(entity("a1", "master", "bot", "SUSPENDED")));
        when(repo.save(any(AgentIdentity.class))).thenAnswer(i -> i.getArgument(0));

        final AgentIdentityDto out = service.activate("master", "a1");

        assertThat(out.status()).isEqualTo("ACTIVE");
    }

    @Test
    void revoke_setsStatusRevoked() {
        when(repo.findById("a1")).thenReturn(Optional.of(entity("a1", "master", "bot", "ACTIVE")));
        when(repo.save(any(AgentIdentity.class))).thenAnswer(i -> i.getArgument(0));

        final AgentIdentityDto out = service.revoke("master", "a1");

        assertThat(out.status()).isEqualTo("REVOKED");
    }

    @Test
    void lifecycleOps_areNullAcrossRealms() {
        when(repo.findById("a1")).thenReturn(Optional.of(entity("a1", "other-realm", "bot", "ACTIVE")));

        assertThat(service.suspend("master", "a1")).isNull();
        verify(repo, never()).save(any());
    }
}
