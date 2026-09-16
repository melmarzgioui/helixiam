package io.helixiam.authorization.amqp.group;

import io.helixiam.authorization.amqp.role.RoleDto;

import java.util.List;

/**
 * Helix IAM E8.5-S4: the Groups admin API's seam onto the realm-domain group store (owned by the
 * subscriber). Routing keys are single tokens (no hyphens) for unambiguous queue binding.
 */
public interface GroupAdminPublisher {

    String EXCHANGE_AUTHORIZATION_GROUP_ADMIN = "exchange-authorization-group-admin";
    String GROUP_ADMIN_LIST = "authorization.group.admin.list";
    String GROUP_ADMIN_CREATE = "authorization.group.admin.create";
    String GROUP_ADMIN_UPDATE = "authorization.group.admin.update";
    String GROUP_ADMIN_DELETE = "authorization.group.admin.delete";
    String GROUP_ADMIN_MEMBERS = "authorization.group.admin.members";
    String GROUP_ADMIN_ADDMEMBER = "authorization.group.admin.addmember";
    String GROUP_ADMIN_REMOVEMEMBER = "authorization.group.admin.removemember";
    String GROUP_ADMIN_ROLES = "authorization.group.admin.roles";
    String GROUP_ADMIN_ASSIGNROLE = "authorization.group.admin.assignrole";
    String GROUP_ADMIN_UNASSIGNROLE = "authorization.group.admin.unassignrole";

    List<GroupDto> list(final String realmId);

    GroupDto create(final GroupWriteDto write);

    GroupDto update(final GroupWriteDto write);

    Boolean delete(final GroupRef ref);

    List<GroupMemberDto> members(final GroupRef ref);

    Boolean addMember(final GroupRef ref);

    Boolean removeMember(final GroupRef ref);

    List<RoleDto> roles(final GroupRef ref);

    Boolean assignRole(final GroupRef ref);

    Boolean unassignRole(final GroupRef ref);
}
