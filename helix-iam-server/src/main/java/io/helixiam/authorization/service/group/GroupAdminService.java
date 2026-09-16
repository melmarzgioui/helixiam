package io.helixiam.authorization.service.group;

import io.helixiam.authorization.domain.group.UserGroup;
import io.helixiam.authorization.domain.group.UserGroupMember;
import io.helixiam.authorization.domain.group.UserGroupRole;
import io.helixiam.authorization.domain.group.admin.GroupDto;
import io.helixiam.authorization.domain.group.admin.GroupMemberDto;
import io.helixiam.authorization.domain.group.admin.GroupRef;
import io.helixiam.authorization.domain.group.admin.GroupWriteDto;
import io.helixiam.authorization.domain.role.admin.RoleDto;
import io.helixiam.authorization.domain.tenant.Tenant;
import io.helixiam.authorization.domain.user.UserRoles;
import io.helixiam.authorization.repository.UserCredentialsRepository;
import io.helixiam.authorization.repository.UserRolesRepository;
import io.helixiam.authorization.repository.group.UserGroupMemberRepository;
import io.helixiam.authorization.repository.group.UserGroupRepository;
import io.helixiam.authorization.repository.group.UserGroupRoleRepository;
import io.helixiam.authorization.repository.tenant.TenantRepository;
import io.helixiam.authorization.repository.tenant.TenantUserRepository;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Optional;

/**
 * Helix IAM E8.5-S4: group administration — hierarchical, realm-scoped user groups with membership and
 * group→role mappings. Members inherit the group's roles. This is the persistence side of the console's
 * Groups screen; it composes with the Users (membership) and Realm roles (role mappings) slices.
 */
@Service
public class GroupAdminService {

    private static final Logger LOG = LogManager.getLogger(GroupAdminService.class);

    private final UserGroupRepository groups;
    private final UserGroupMemberRepository members;
    private final UserGroupRoleRepository groupRoles;
    private final UserRolesRepository roles;
    private final UserCredentialsRepository users;
    private final TenantUserRepository tenantUsers;
    private final TenantRepository tenants;

    public GroupAdminService(final UserGroupRepository groups, final UserGroupMemberRepository members,
                             final UserGroupRoleRepository groupRoles, final UserRolesRepository roles,
                             final UserCredentialsRepository users, final TenantUserRepository tenantUsers,
                             final TenantRepository tenants) {
        this.groups = groups;
        this.members = members;
        this.groupRoles = groupRoles;
        this.roles = roles;
        this.users = users;
        this.tenantUsers = tenantUsers;
        this.tenants = tenants;
    }

    /** Every group in the realm, each with its member count and the names of its mapped roles. */
    public List<GroupDto> list(final String realmId) {
        return groups.findAllByTenantId(realmId).stream().map(this::toDto).toList();
    }

    /** Creates a group; idempotent on (parent, name) — returns the existing group if already present. */
    @Transactional
    public GroupDto create(final GroupWriteDto write) {
        ensureTenant(write.realmId());
        if (groups.existsByTenantIdAndParentIdAndName(write.realmId(), write.parentId(), write.name())) {
            return groups.findAllByTenantId(write.realmId()).stream()
                    .filter(g -> write.name().equals(g.getName()) && java.util.Objects.equals(write.parentId(), g.getParentId()))
                    .findFirst().map(this::toDto).orElse(null);
        }
        final UserGroup saved = groups.save(new UserGroup(write.name(), write.parentId(), write.realmId()));
        LOG.debug("Created group {} in realm {}", write.name(), write.realmId());
        return toDto(saved);
    }

    /** Renames / reparents a group; {@code null} if it isn't in this realm. */
    @Transactional
    public GroupDto update(final GroupWriteDto write) {
        final Optional<UserGroup> existing = groups.findById(write.groupId());
        if (existing.isEmpty() || !write.realmId().equals(existing.get().getTenantId())) {
            return null;
        }
        final UserGroup group = existing.get();
        group.setName(write.name());
        group.setParentId(write.parentId());
        return toDto(groups.save(group));
    }

    /** Deletes a group and everything under it (child groups, members, role mappings); {@code false} if absent. */
    @Transactional
    public boolean delete(final String realmId, final String groupId) {
        final Optional<UserGroup> group = groups.findById(groupId);
        if (group.isEmpty() || !realmId.equals(group.get().getTenantId())) {
            return false;
        }
        deleteRecursively(group.get());
        LOG.debug("Deleted group {} from realm {}", groupId, realmId);
        return true;
    }

    private void deleteRecursively(final UserGroup group) {
        groups.findAllByParentId(group.getGroupId()).forEach(this::deleteRecursively);
        groups.delete(group); // member + role-map rows cascade via FK
    }

    /** The users who belong to a group, with their usernames. */
    public List<GroupMemberDto> listMembers(final GroupRef ref) {
        return members.findAllByGroupId(ref.groupId()).stream()
                .map(m -> users.findByUserId(m.getUserId())
                        .map(u -> new GroupMemberDto(u.getUserId(), u.getUsername()))
                        .orElse(new GroupMemberDto(m.getUserId(), m.getUserId())))
                .toList();
    }

    /** Adds a user to a group; {@code false} if the user is not a member of the realm. */
    @Transactional
    public boolean addMember(final GroupRef ref) {
        if (tenantUsers.findByTenantIdAndUserId(ref.realmId(), ref.userId()).isEmpty()) {
            return false;
        }
        if (members.findByGroupIdAndUserId(ref.groupId(), ref.userId()).isEmpty()) {
            members.save(new UserGroupMember(ref.groupId(), ref.userId()));
            LOG.debug("Added user {} to group {}", ref.userId(), ref.groupId());
        }
        return true;
    }

    /** Removes a user from a group; {@code false} if they weren't a member. */
    @Transactional
    public boolean removeMember(final GroupRef ref) {
        return members.findByGroupIdAndUserId(ref.groupId(), ref.userId()).map(m -> {
            members.delete(m);
            return true;
        }).orElse(false);
    }

    /** The realm roles mapped onto a group. */
    public List<RoleDto> listRoles(final GroupRef ref) {
        return groupRoles.findAllByGroupId(ref.groupId()).stream()
                .map(gr -> roles.findById(gr.getRoleId())
                        .map(r -> new RoleDto(ref.realmId(), r.getRoleId(), r.getName(), r.isSystemRole(), r.isDefaultRole()))
                        .orElse(null))
                .filter(java.util.Objects::nonNull)
                .toList();
    }

    /** Maps a realm role onto a group; {@code false} if the role isn't in this realm. */
    @Transactional
    public boolean assignRole(final GroupRef ref) {
        final Optional<UserRoles> role = roles.findById(ref.roleId());
        if (role.isEmpty() || !ref.realmId().equals(role.get().getTenantId())) {
            return false;
        }
        if (groupRoles.findByGroupIdAndRoleId(ref.groupId(), ref.roleId()).isEmpty()) {
            groupRoles.save(new UserGroupRole(ref.groupId(), ref.roleId()));
            LOG.debug("Mapped role {} onto group {}", ref.roleId(), ref.groupId());
        }
        return true;
    }

    /** Removes a role mapping from a group; {@code false} if it wasn't mapped. */
    @Transactional
    public boolean unassignRole(final GroupRef ref) {
        return groupRoles.findByGroupIdAndRoleId(ref.groupId(), ref.roleId()).map(gr -> {
            groupRoles.delete(gr);
            return true;
        }).orElse(false);
    }

    private GroupDto toDto(final UserGroup g) {
        final List<String> roleNames = groupRoles.findAllByGroupId(g.getGroupId()).stream()
                .map(gr -> roles.findById(gr.getRoleId()).map(UserRoles::getName).orElse(null))
                .filter(java.util.Objects::nonNull)
                .toList();
        return new GroupDto(g.getTenantId(), g.getGroupId(), g.getName(), g.getParentId(),
                members.countByGroupId(g.getGroupId()), roleNames);
    }

    private void ensureTenant(final String realmId) {
        if (tenants.findById(realmId).isEmpty()) {
            final Tenant tenant = new Tenant();
            tenant.setTenantId(realmId);
            tenants.save(tenant);
        }
    }
}
