/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.amqp.scope.adapter;

import com.fasterxml.jackson.core.type.TypeReference;
import io.helixiam.authorization.amqp.scope.ClaimDto;
import io.helixiam.authorization.amqp.scope.ClaimScopePublisher;
import io.helixiam.authorization.amqp.scope.ClaimWriteDto;
import io.helixiam.authorization.amqp.scope.ClientScopeDto;
import io.helixiam.authorization.amqp.scope.ScopeDetailDto;
import io.helixiam.authorization.amqp.scope.ScopeRef;
import io.helixiam.authorization.amqp.scope.ScopeWriteDto;
import io.helixiam.authorization.amqp.scope.SubjectClaimDto;
import io.helixiam.authorization.amqp.support.DtoBridge;
import io.helixiam.authorization.service.scope.ClaimScopeAdminService;
import io.helixiam.authorization.support.RealmScopedKey;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * Strip-RabbitMQ (Task 3): in-process adapter replacing the former AMQP transport of
 * {@link ClaimScopePublisher}.
 */
@Component
public class ClaimScopeLocalAdapter implements ClaimScopePublisher {

    private final ClaimScopeAdminService service;
    private final DtoBridge bridge;

    public ClaimScopeLocalAdapter(final ClaimScopeAdminService service, final DtoBridge bridge) {
        this.service = service;
        this.bridge = bridge;
    }

    private io.helixiam.authorization.domain.scope.admin.ScopeRef ref(final ScopeRef ref) {
        return bridge.to(ref, io.helixiam.authorization.domain.scope.admin.ScopeRef.class);
    }

    @Override
    public List<ClaimDto> claims(final String realmId) {
        return bridge.to(service.listClaims(realmId), new TypeReference<List<ClaimDto>>() { });
    }

    @Override
    public ClaimDto createClaim(final ClaimWriteDto write) {
        return bridge.to(service.createClaim(
                bridge.to(write, io.helixiam.authorization.domain.scope.admin.ClaimWriteDto.class)), ClaimDto.class);
    }

    @Override
    public ClaimDto updateClaim(final ClaimWriteDto write) {
        return bridge.to(service.updateClaim(
                bridge.to(write, io.helixiam.authorization.domain.scope.admin.ClaimWriteDto.class)), ClaimDto.class);
    }

    @Override
    public Boolean deleteClaim(final ScopeRef ref) {
        return service.deleteClaim(ref.realmId(), ref.claimId());
    }

    @Override
    public List<ClientScopeDto> scopes(final String realmId) {
        return bridge.to(service.listScopes(realmId), new TypeReference<List<ClientScopeDto>>() { });
    }

    @Override
    public ScopeDetailDto scope(final ScopeRef ref) {
        return bridge.to(service.getScope(ref.realmId(), ref.scopeId()), ScopeDetailDto.class);
    }

    @Override
    public ClientScopeDto createScope(final ScopeWriteDto write) {
        return bridge.to(service.createScope(
                bridge.to(write, io.helixiam.authorization.domain.scope.admin.ScopeWriteDto.class)),
                ClientScopeDto.class);
    }

    @Override
    public Boolean deleteScope(final ScopeRef ref) {
        return service.deleteScope(ref.realmId(), ref.scopeId());
    }

    @Override
    public Boolean addClaim(final ScopeRef ref) {
        return service.addClaim(ref(ref));
    }

    @Override
    public Boolean removeClaim(final ScopeRef ref) {
        return service.removeClaim(ref(ref));
    }

    @Override
    public SubjectClaimDto subjectClaim(final String realmId) {
        return new SubjectClaimDto(realmId, service.getSubjectClaim(realmId));
    }

    @Override
    public SubjectClaimDto setSubjectClaim(final SubjectClaimDto write) {
        return bridge.to(service.setSubjectClaim(
                bridge.to(write, io.helixiam.authorization.domain.scope.admin.SubjectClaimDto.class)),
                SubjectClaimDto.class);
    }

    @Override
    public String subjectForClient(final String clientId) {
        final String[] parts = RealmScopedKey.split(clientId);
        return service.resolveSubjectClaimForClient(parts[0], parts[1]);
    }
}
