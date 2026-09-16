/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.amqp.authz.adapter;

import com.fasterxml.jackson.core.type.TypeReference;
import io.helixiam.authorization.amqp.authz.AuthorizationPublisher;
import io.helixiam.authorization.amqp.authz.AuthzEvalRequest;
import io.helixiam.authorization.amqp.authz.AuthzEvalResult;
import io.helixiam.authorization.amqp.authz.AuthzPermissionDto;
import io.helixiam.authorization.amqp.authz.AuthzPolicyDto;
import io.helixiam.authorization.amqp.authz.AuthzRef;
import io.helixiam.authorization.amqp.authz.AuthzResourceDto;
import io.helixiam.authorization.amqp.authz.AuthzScopeDto;
import io.helixiam.authorization.amqp.authz.AuthzServerDto;
import io.helixiam.authorization.amqp.support.DtoBridge;
import io.helixiam.authorization.service.authz.AuthorizationAdminService;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * Strip-RabbitMQ (Task 3): in-process adapter replacing the former AMQP transport of
 * {@link AuthorizationPublisher}.
 */
@Component
public class AuthorizationLocalAdapter implements AuthorizationPublisher {


    private final AuthorizationAdminService service;
    private final DtoBridge bridge;

    public AuthorizationLocalAdapter(final AuthorizationAdminService service, final DtoBridge bridge) {
        this.service = service;
        this.bridge = bridge;
    }

    @Override
    public AuthzServerDto getServer(final AuthzRef ref) {
        return bridge.to(service.getServer(ref.realmId(), ref.clientId()), AuthzServerDto.class);
    }

    @Override
    public AuthzServerDto setServer(final AuthzServerDto write) {
        return bridge.to(service.setServer(
                bridge.to(write, io.helixiam.authorization.domain.authz.AuthzServerDto.class)),
                AuthzServerDto.class);
    }

    @Override
    public List<AuthzScopeDto> listScopes(final AuthzRef ref) {
        return bridge.to(service.listScopes(ref.realmId(), ref.clientId()),
                new TypeReference<List<AuthzScopeDto>>() { });
    }

    @Override
    public AuthzScopeDto createScope(final AuthzScopeDto write) {
        return bridge.to(service.createScope(
                bridge.to(write, io.helixiam.authorization.domain.authz.AuthzScopeDto.class)),
                AuthzScopeDto.class);
    }

    @Override
    public Boolean deleteScope(final AuthzRef ref) {
        return service.deleteScope(ref.realmId(), ref.clientId(), ref.name());
    }

    @Override
    public List<AuthzResourceDto> listResources(final AuthzRef ref) {
        return bridge.to(service.listResources(ref.realmId(), ref.clientId()),
                new TypeReference<List<AuthzResourceDto>>() { });
    }

    @Override
    public AuthzResourceDto createResource(final AuthzResourceDto write) {
        return bridge.to(service.createResource(
                bridge.to(write, io.helixiam.authorization.domain.authz.AuthzResourceDto.class)),
                AuthzResourceDto.class);
    }

    @Override
    public Boolean deleteResource(final AuthzRef ref) {
        return service.deleteResource(ref.realmId(), ref.clientId(), ref.name());
    }

    @Override
    public List<AuthzPolicyDto> listPolicies(final AuthzRef ref) {
        return bridge.to(service.listPolicies(ref.realmId(), ref.clientId()),
                new TypeReference<List<AuthzPolicyDto>>() { });
    }

    @Override
    public AuthzPolicyDto createPolicy(final AuthzPolicyDto write) {
        return bridge.to(service.createPolicy(
                bridge.to(write, io.helixiam.authorization.domain.authz.AuthzPolicyDto.class)),
                AuthzPolicyDto.class);
    }

    @Override
    public Boolean deletePolicy(final AuthzRef ref) {
        return service.deletePolicy(ref.realmId(), ref.clientId(), ref.name());
    }

    @Override
    public List<AuthzPermissionDto> listPermissions(final AuthzRef ref) {
        return bridge.to(service.listPermissions(ref.realmId(), ref.clientId()),
                new TypeReference<List<AuthzPermissionDto>>() { });
    }

    @Override
    public AuthzPermissionDto createPermission(final AuthzPermissionDto write) {
        return bridge.to(service.createPermission(
                bridge.to(write, io.helixiam.authorization.domain.authz.AuthzPermissionDto.class)),
                AuthzPermissionDto.class);
    }

    @Override
    public Boolean deletePermission(final AuthzRef ref) {
        return service.deletePermission(ref.realmId(), ref.clientId(), ref.name());
    }

    @Override
    public AuthzEvalResult evaluate(final AuthzEvalRequest req) {
        return bridge.to(service.evaluate(
                bridge.to(req, io.helixiam.authorization.domain.authz.AuthzEvalRequest.class)),
                AuthzEvalResult.class);
    }
}
