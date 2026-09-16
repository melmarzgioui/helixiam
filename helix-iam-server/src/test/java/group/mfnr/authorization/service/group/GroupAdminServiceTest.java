package group.mfnr.authorization.service.group;

import group.mfnr.authorization.domain.group.UserGroup;
import group.mfnr.authorization.domain.group.UserGroupMember;
import group.mfnr.authorization.domain.group.UserGroupRole;
import group.mfnr.authorization.domain.group.admin.GroupDto;
import group.mfnr.authorization.domain.group.admin.GroupRef;
import group.mfnr.authorization.domain.group.admin.GroupWriteDto;
import group.mfnr.authorization.domain.tenant.TenantUser;
import group.mfnr.authorization.domain.user.UserRoles;
import group.mfnr.authorization.repository.UserCredentialsRepository;
import group.mfnr.authorization.repository.UserRolesRepository;
import group.mfnr.authorization.repository.group.UserGroupMemberRepository;
import group.mfnr.authorization.repository.group.UserGroupRepository;
import group.mfnr.authorization.repository.group.UserGroupRoleRepository;
import group.mfnr.authorization.repository.tenant.TenantRepository;
import group.mfnr.authorization.repository.tenant.TenantUserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;
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
 * Helix IAM E8.5-S4: group administration — hierarchical groups, membership, and group→role mappings.
 */
class GroupAdminServiceTest {

    private UserGroupRepository groups;
    private UserGroupMemberRepository members;
    private UserGroupRoleRepository groupRoles;
    private UserRolesRepository roles;
    private UserCredentialsRepository users;
    private TenantUserRepository tenantUsers;
    private TenantRepository tenants;
    private GroupAdminService service;

    @BeforeEach
    void setUp() {
        groups = mock(UserGroupRepository.class);
        members = mock(UserGroupMemberRepository.class);
        groupRoles = mock(UserGroupRoleRepository.class);
        roles = mock(UserRolesRepository.class);
        users = mock(UserCredentialsRepository.class);
        tenantUsers = mock(TenantUserRepository.class);
        tenants = mock(TenantRepository.class);
        service = new GroupAdminService(groups, members, groupRoles, roles, users, tenantUsers, tenants);
    }

    @Test
    void list_returnsGroups_withMemberCountsAndRoleNames() {
        final UserGroup g = new UserGroup("Civil servants", null, "gov");
        when(groups.findAllByTenantId("gov")).thenReturn(List.of(g));
        when(members.countByGroupId(g.getGroupId())).thenReturn(3L);
        when(groupRoles.findAllByGroupId(g.getGroupId())).thenReturn(List.of(new UserGroupRole(g.getGroupId(), "role-1")));
        final UserRoles role = new UserRoles("auditors", "gov");
        when(roles.findById("role-1")).thenReturn(Optional.of(role));

        final List<GroupDto> result = service.list("gov");

        assertEquals(1, result.size());
        assertEquals("Civil servants", result.get(0).name());
        assertEquals(3L, result.get(0).memberCount());
        assertEquals(List.of("auditors"), result.get(0).roleNames());
    }

    @Test
    void create_ensuresTenant_andPersistsTheGroup() {
        when(tenants.findById("gov")).thenReturn(Optional.of(mock(group.mfnr.authorization.domain.tenant.Tenant.class)));
        when(groups.existsByTenantIdAndParentIdAndName("gov", null, "Contractors")).thenReturn(false);
        when(groups.save(any(UserGroup.class))).thenAnswer(inv -> inv.getArgument(0));

        final GroupDto dto = service.create(new GroupWriteDto("gov", null, "Contractors", null));

        assertEquals("Contractors", dto.name());
        verify(groups).save(any(UserGroup.class));
    }

    @Test
    void addMember_isRejected_whenUserIsNotInTheRealm() {
        when(tenantUsers.findByTenantIdAndUserId("gov", "u-1")).thenReturn(Optional.empty());

        assertFalse(service.addMember(new GroupRef("gov", "g-1", "u-1", null)));
        verify(members, never()).save(any());
    }

    @Test
    void addMember_savesMembership_whenUserBelongsToTheRealm() {
        when(tenantUsers.findByTenantIdAndUserId("gov", "u-1")).thenReturn(Optional.of(new TenantUser()));
        when(members.findByGroupIdAndUserId("g-1", "u-1")).thenReturn(Optional.empty());

        assertTrue(service.addMember(new GroupRef("gov", "g-1", "u-1", null)));
        verify(members).save(any(UserGroupMember.class));
    }

    @Test
    void delete_recursivelyRemovesChildGroups() {
        final UserGroup parent = new UserGroup("Parent", null, "gov");
        final UserGroup child = new UserGroup("Child", parent.getGroupId(), "gov");
        when(groups.findById(parent.getGroupId())).thenReturn(Optional.of(parent));
        when(groups.findAllByParentId(parent.getGroupId())).thenReturn(List.of(child));
        when(groups.findAllByParentId(child.getGroupId())).thenReturn(List.of());

        assertTrue(service.delete("gov", parent.getGroupId()));

        verify(groups).delete(child);
        verify(groups).delete(parent);
    }

    @Test
    void assignRole_mapsRealmRoleOntoGroup() {
        final UserGroup g = new UserGroup("Auditors", null, "gov");
        when(groups.findById(g.getGroupId())).thenReturn(Optional.of(g));
        final UserRoles role = new UserRoles("auditors", "gov");
        when(roles.findById("role-1")).thenReturn(Optional.of(role));
        when(groupRoles.findByGroupIdAndRoleId(g.getGroupId(), "role-1")).thenReturn(Optional.empty());

        assertTrue(service.assignRole(new GroupRef("gov", g.getGroupId(), null, "role-1")));
        verify(groupRoles).save(any(UserGroupRole.class));
    }
}
