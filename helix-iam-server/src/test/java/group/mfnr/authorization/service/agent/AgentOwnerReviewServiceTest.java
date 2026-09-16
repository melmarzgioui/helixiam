package group.mfnr.authorization.service.agent;

import group.mfnr.authorization.domain.agent.AgentOwnerReviewDto;
import group.mfnr.authorization.domain.agent.AgentIdentity;
import group.mfnr.authorization.domain.tenant.TenantUser;
import group.mfnr.authorization.domain.user.UserCredentials;
import group.mfnr.authorization.repository.agent.AgentIdentityRepository;
import group.mfnr.authorization.repository.UserCredentialsRepository;
import group.mfnr.authorization.repository.tenant.TenantUserRepository;
import group.mfnr.authorization.service.audit.AuditLogService;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Owner-review lists every agent with its owner-integrity verdict, and the deprovisioning cascade suspends
 * the ACTIVE agents of a user who has just been disabled/deleted — so a departing human never leaves live,
 * unattended non-human identities behind.
 */
class AgentOwnerReviewServiceTest {

    private final AgentIdentityRepository agents = mock(AgentIdentityRepository.class);
    private final TenantUserRepository tenantUsers = mock(TenantUserRepository.class);
    private final UserCredentialsRepository users = mock(UserCredentialsRepository.class);
    private final AuditLogService audit = mock(AuditLogService.class);
    private final AgentOwnerReviewService service = new AgentOwnerReviewService(agents, tenantUsers, users, audit);

    private static AgentIdentity agent(final String id, final String owner, final String status) {
        final AgentIdentity a = new AgentIdentity();
        a.setId(id); a.setRealmId("master"); a.setName("agent-" + id); a.setOwner(owner); a.setStatus(status);
        return a;
    }

    private static UserCredentials user(final String userId, final String username, final String email, final boolean enabled) {
        final UserCredentials u = mock(UserCredentials.class);
        when(u.getUserId()).thenReturn(userId);
        when(u.getUsername()).thenReturn(username);
        when(u.getEmail()).thenReturn(email);
        when(u.isDisabled()).thenReturn(!enabled); // isEnabled() is a stub; classification keys on isDisabled()
        return u;
    }

    private void realmHasUsers(final UserCredentials... us) {
        final List<TenantUser> links = new java.util.ArrayList<>();
        for (final UserCredentials u : us) {
            final String uid = u.getUserId();
            final TenantUser link = mock(TenantUser.class);
            when(link.getUserId()).thenReturn(uid);
            links.add(link);
            when(users.findByUserId(uid)).thenReturn(Optional.of(u));
        }
        when(tenantUsers.findAllByTenantId("master")).thenReturn(links);
    }

    @Test
    void reviewClassifiesEachAgentsOwner() {
        realmHasUsers(user("u1", "alice", "alice@acme.example", true),
                      user("u2", "bob", "bob@acme.example", false));
        when(agents.findAllByRealmIdOrderByCreatedAtAsc("master")).thenReturn(List.of(
                agent("a", "alice@acme.example", "ACTIVE"),   // VALID
                agent("b", "bob", "ACTIVE"),                  // ORPHANED (bob disabled)
                agent("c", "ghost@acme.example", "ACTIVE"))); // UNKNOWN

        final List<AgentOwnerReviewDto> review = service.review("master");

        assertThat(review).extracting(AgentOwnerReviewDto::id, AgentOwnerReviewDto::ownerStatus)
                .containsExactly(
                        org.assertj.core.groups.Tuple.tuple("a", "VALID"),
                        org.assertj.core.groups.Tuple.tuple("b", "ORPHANED"),
                        org.assertj.core.groups.Tuple.tuple("c", "UNKNOWN"));
    }

    @Test
    void cascadeSuspendsOnlyTheDepartedOwnersActiveAgents() {
        when(agents.findAllByRealmIdOrderByCreatedAtAsc("master")).thenReturn(List.of(
                agent("a", "bob@acme.example", "ACTIVE"),   // owned by bob → suspend
                agent("b", "bob", "ACTIVE"),                // owned by bob (username) → suspend
                agent("c", "bob@acme.example", "REVOKED"),  // already inert → leave
                agent("d", "alice@acme.example", "ACTIVE")));// someone else → leave

        final int suspended = service.cascadeOnDeprovision("master", "bob", "bob@acme.example");

        assertThat(suspended).isEqualTo(2);
        final ArgumentCaptor<AgentIdentity> saved = ArgumentCaptor.forClass(AgentIdentity.class);
        verify(agents, times(2)).save(saved.capture());
        assertThat(saved.getAllValues()).extracting(AgentIdentity::getId).containsExactlyInAnyOrder("a", "b");
        assertThat(saved.getAllValues()).allMatch(a -> "SUSPENDED".equals(a.getStatus()));
        verify(audit, times(2)).record(any());
    }

    @Test
    void cascadeIsANoOpWhenTheOwnerHasNoAgents() {
        when(agents.findAllByRealmIdOrderByCreatedAtAsc("master")).thenReturn(List.of(
                agent("d", "alice@acme.example", "ACTIVE")));

        assertThat(service.cascadeOnDeprovision("master", "bob", "bob@acme.example")).isZero();
        verify(agents, never()).save(any());
        verify(audit, never()).record(any());
    }
}
