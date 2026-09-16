package group.mfnr.authorization.service.org;

import group.mfnr.authorization.domain.org.Organization;
import group.mfnr.authorization.domain.org.OrganizationMember;
import group.mfnr.authorization.domain.org.admin.OrgDto;
import group.mfnr.authorization.domain.org.admin.OrgMembershipDto;
import group.mfnr.authorization.domain.org.admin.OrgRef;
import group.mfnr.authorization.domain.org.admin.OrgWriteDto;
import group.mfnr.authorization.domain.tenant.TenantUser;
import group.mfnr.authorization.domain.user.UserCredentials;
import group.mfnr.authorization.repository.UserCredentialsRepository;
import group.mfnr.authorization.repository.org.OrganizationMemberRepository;
import group.mfnr.authorization.repository.org.OrganizationRepository;
import group.mfnr.authorization.repository.tenant.TenantRepository;
import group.mfnr.authorization.repository.tenant.TenantUserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Helix IAM Organizations: B2B organization administration — CRUD, membership, and the memberships-for-user
 * lookup that feeds the {@code organizations} token claim.
 */
class OrganizationAdminServiceTest {

    private OrganizationRepository organizations;
    private OrganizationMemberRepository members;
    private UserCredentialsRepository users;
    private TenantUserRepository tenantUsers;
    private TenantRepository tenants;
    private OrganizationAdminService service;

    @BeforeEach
    void setUp() {
        organizations = mock(OrganizationRepository.class);
        members = mock(OrganizationMemberRepository.class);
        users = mock(UserCredentialsRepository.class);
        tenantUsers = mock(TenantUserRepository.class);
        tenants = mock(TenantRepository.class);
        when(organizations.save(any())).thenAnswer(i -> i.getArgument(0));
        when(members.save(any())).thenAnswer(i -> i.getArgument(0));
        service = new OrganizationAdminService(organizations, members, users, tenantUsers, tenants);
    }

    @Test
    void list_returnsOrgs_withMemberCount() {
        final Organization o = new Organization("gov", "acme", "Acme Inc", "acme.com,acme.io", true);
        when(organizations.findAllByTenantId("gov")).thenReturn(List.of(o));
        when(members.countByOrgId(o.getOrgId())).thenReturn(2L);

        final List<OrgDto> result = service.list("gov");

        assertEquals(1, result.size());
        final OrgDto dto = result.get(0);
        assertEquals("acme", dto.name());
        assertEquals("Acme Inc", dto.displayName());
        assertEquals(List.of("acme.com", "acme.io"), dto.domains());
        assertEquals(2L, dto.memberCount());
        assertTrue(dto.enabled());
    }

    @Test
    void create_normalisesDomains_andPersists() {
        when(organizations.existsByTenantIdAndName("gov", "acme")).thenReturn(false);
        when(tenants.findById("gov")).thenReturn(Optional.of(mock(group.mfnr.authorization.domain.tenant.Tenant.class)));

        final OrgDto dto = service.create(new OrgWriteDto("gov", null, "acme", "Acme Inc",
                List.of("Acme.com", " acme.com ", "ACME.IO"), true));

        assertEquals("acme", dto.name());
        assertEquals(List.of("acme.com", "acme.io"), dto.domains());
        verify(organizations).save(any());
    }

    @Test
    void create_rejectsDuplicateName() {
        when(organizations.existsByTenantIdAndName("gov", "acme")).thenReturn(true);
        when(tenants.findById("gov")).thenReturn(Optional.of(mock(group.mfnr.authorization.domain.tenant.Tenant.class)));

        assertThrows(IllegalArgumentException.class,
                () -> service.create(new OrgWriteDto("gov", null, "acme", null, List.of(), true)));
        verify(organizations, never()).save(any());
    }

    @Test
    void create_rejectsBlankName() {
        assertThrows(IllegalArgumentException.class,
                () -> service.create(new OrgWriteDto("gov", null, "  ", null, List.of(), true)));
    }

    @Test
    void update_rejectsCrossRealmOrg_returnsNull() {
        final Organization o = new Organization("other", "acme", null, null, true);
        when(organizations.findById(o.getOrgId())).thenReturn(Optional.of(o));

        assertTrue(service.update(new OrgWriteDto("gov", o.getOrgId(), "acme", null, List.of(), true)) == null);
    }

    @Test
    void addMember_failsWhenUserNotInRealm() {
        final Organization o = new Organization("gov", "acme", null, null, true);
        when(organizations.findById(o.getOrgId())).thenReturn(Optional.of(o));
        when(tenantUsers.findByTenantIdAndUserId("gov", "u1")).thenReturn(Optional.empty());

        assertFalse(service.addMember(new OrgRef("gov", o.getOrgId(), "u1", "member")));
        verify(members, never()).save(any());
    }

    @Test
    void addMember_defaultsRoleToMember_andIsIdempotent() {
        final Organization o = new Organization("gov", "acme", null, null, true);
        when(organizations.findById(o.getOrgId())).thenReturn(Optional.of(o));
        when(tenantUsers.findByTenantIdAndUserId("gov", "u1")).thenReturn(Optional.of(new TenantUser()));
        when(members.findByOrgIdAndUserId(o.getOrgId(), "u1")).thenReturn(Optional.empty());

        assertTrue(service.addMember(new OrgRef("gov", o.getOrgId(), "u1", null)));
        verify(members).save(any(OrganizationMember.class));
    }

    @Test
    void membershipsForUser_skipsDisabledOrgs_andUsesMutableLists() {
        final Organization enabled = new Organization("gov", "acme", null, null, true);
        final Organization disabled = new Organization("gov", "globex", null, null, false);
        when(members.findAllByUserId("u1")).thenReturn(List.of(
                new OrganizationMember(enabled.getOrgId(), "u1", "admin"),
                new OrganizationMember(disabled.getOrgId(), "u1", "member")));
        when(organizations.findById(enabled.getOrgId())).thenReturn(Optional.of(enabled));
        when(organizations.findById(disabled.getOrgId())).thenReturn(Optional.of(disabled));

        final List<OrgMembershipDto> result = service.membershipsForUser("u1");

        assertEquals(1, result.size());
        assertEquals("acme", result.get(0).name());
        assertEquals(List.of("admin"), result.get(0).roles());
        // Must be a mutable ArrayList (SAS Jackson allowlist rejects immutable collections in token claims).
        result.get(0).roles().add("extra");
        assertEquals(2, result.get(0).roles().size());
    }

    @Test
    void listMembers_resolvesUsernames_andRole() {
        final Organization o = new Organization("gov", "acme", null, null, true);
        when(members.findAllByOrgId(o.getOrgId())).thenReturn(List.of(new OrganizationMember(o.getOrgId(), "u1", "admin")));
        final UserCredentials user = new UserCredentials();
        user.setUsername("alice");
        when(users.findByUserId("u1")).thenReturn(Optional.of(user));

        final var result = service.listMembers(new OrgRef("gov", o.getOrgId(), null, null));

        assertEquals(1, result.size());
        assertEquals("alice", result.get(0).username());
        assertEquals("admin", result.get(0).role());
    }
}
