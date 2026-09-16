/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.amqp.group.adapter;

import com.fasterxml.jackson.core.type.TypeReference;
import io.helixiam.authorization.amqp.group.GroupAdminPublisher;
import io.helixiam.authorization.amqp.group.GroupDto;
import io.helixiam.authorization.amqp.group.GroupMemberDto;
import io.helixiam.authorization.amqp.group.GroupRef;
import io.helixiam.authorization.amqp.group.GroupWriteDto;
import io.helixiam.authorization.amqp.role.RoleDto;
import io.helixiam.authorization.amqp.support.DtoBridge;
import io.helixiam.authorization.service.group.GroupAdminService;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * Strip-RabbitMQ (Task 3): in-process adapter replacing the former AMQP transport of
 * {@link GroupAdminPublisher}.
 */
@Component
public class GroupAdminLocalAdapter implements GroupAdminPublisher {

    private final GroupAdminService service;
    private final DtoBridge bridge;

    public GroupAdminLocalAdapter(final GroupAdminService service, final DtoBridge bridge) {
        this.service = service;
        this.bridge = bridge;
    }

    private io.helixiam.authorization.domain.group.admin.GroupRef ref(final GroupRef ref) {
        return bridge.to(ref, io.helixiam.authorization.domain.group.admin.GroupRef.class);
    }

    @Override
    public List<GroupDto> list(final String realmId) {
        return bridge.to(service.list(realmId), new TypeReference<List<GroupDto>>() { });
    }

    @Override
    public GroupDto create(final GroupWriteDto write) {
        return bridge.to(service.create(
                bridge.to(write, io.helixiam.authorization.domain.group.admin.GroupWriteDto.class)), GroupDto.class);
    }

    @Override
    public GroupDto update(final GroupWriteDto write) {
        return bridge.to(service.update(
                bridge.to(write, io.helixiam.authorization.domain.group.admin.GroupWriteDto.class)), GroupDto.class);
    }

    @Override
    public Boolean delete(final GroupRef ref) {
        return service.delete(ref.realmId(), ref.groupId());
    }

    @Override
    public List<GroupMemberDto> members(final GroupRef ref) {
        return bridge.to(service.listMembers(ref(ref)), new TypeReference<List<GroupMemberDto>>() { });
    }

    @Override
    public Boolean addMember(final GroupRef ref) {
        return service.addMember(ref(ref));
    }

    @Override
    public Boolean removeMember(final GroupRef ref) {
        return service.removeMember(ref(ref));
    }

    @Override
    public List<RoleDto> roles(final GroupRef ref) {
        return bridge.to(service.listRoles(ref(ref)), new TypeReference<List<RoleDto>>() { });
    }

    @Override
    public Boolean assignRole(final GroupRef ref) {
        return service.assignRole(ref(ref));
    }

    @Override
    public Boolean unassignRole(final GroupRef ref) {
        return service.unassignRole(ref(ref));
    }
}
