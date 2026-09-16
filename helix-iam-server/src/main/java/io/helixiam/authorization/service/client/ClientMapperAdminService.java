/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.service.client;

import io.helixiam.authorization.domain.client.mapper.ClientProtocolMapperEntity;
import io.helixiam.authorization.domain.client.mapper.ProtocolMapperDto;
import io.helixiam.authorization.domain.client.mapper.ProtocolMapperWriteDto;
import io.helixiam.authorization.repository.ClientProtocolMapperRepository;
import io.helixiam.authorization.repository.ServiceProviderRepository;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Optional;

/**
 * Helix IAM (Wave 3): per-client protocol mapper administration — register/update/delete the standalone
 * mappers that inject extra claims (a user attribute, or a hardcoded value) into a client's tokens. Mirrors
 * the client / scope admin slices. {@link #mappersForClient} is the runtime lookup the token customizer uses
 * at issuance.
 */
@Service
public class ClientMapperAdminService {

    private static final Logger LOG = LogManager.getLogger(ClientMapperAdminService.class);

    private final ClientProtocolMapperRepository repository;
    private final ServiceProviderRepository clients;

    @Autowired
    public ClientMapperAdminService(final ClientProtocolMapperRepository repository,
                                    final ServiceProviderRepository clients) {
        this.repository = repository;
        this.clients = clients;
    }

    /** A client's protocol mappers (by realm + clientId), ordered by name. */
    @Transactional(readOnly = true)
    public List<ProtocolMapperDto> list(final String realmId, final String clientId) {
        return repository.findAllByRealmIdAndClientIdOrderByName(realmId, clientId).stream().map(this::toDto).toList();
    }

    /** Registers a new mapper for a client; returns it with its generated id. */
    @Transactional
    public ProtocolMapperDto create(final ProtocolMapperWriteDto write) {
        final ClientProtocolMapperEntity entity = new ClientProtocolMapperEntity();
        entity.setRealmId(blankToDefault(write.realmId()));
        entity.setClientId(write.clientId());
        apply(entity, write);
        final ClientProtocolMapperEntity saved = repository.save(entity);
        LOG.debug("Created mapper {} on client {} in realm {}", write.name(), write.clientId(), write.realmId());
        return toDto(saved);
    }

    /** Updates a mapper, but only when it belongs to the addressed client. */
    @Transactional
    public Optional<ProtocolMapperDto> update(final ProtocolMapperWriteDto write) {
        return repository.findByMapperIdAndRealmIdAndClientId(write.mapperId(), blankToDefault(write.realmId()), write.clientId())
                .map(entity -> {
                    apply(entity, write);
                    return toDto(repository.save(entity));
                });
    }

    /** Removes a mapper; {@code false} when it is absent / not the client's. */
    @Transactional
    public boolean delete(final String realmId, final String clientId, final String mapperId) {
        return repository.findByMapperIdAndRealmIdAndClientId(mapperId, realmId, clientId).map(entity -> {
            repository.delete(entity);
            LOG.debug("Deleted mapper {} from client {} in realm {}", mapperId, clientId, realmId);
            return true;
        }).orElse(false);
    }

    /**
     * The protocol mappers for an OAuth client ({@code client_id} <b>within {@code realmId}</b>).
     * Used by the token customizer at issuance; returns an empty list when the client is unknown.
     * Realm-scoped so a client id reused across realms resolves the right client.
     */
    @Transactional(readOnly = true)
    public List<ProtocolMapperDto> mappersForClient(final String realmId, final String clientId) {
        return clients.findByClientIdAndRealmIdAndDeleted(clientId, realmId, false)
                .map(c -> list(c.getTenantId(), clientId))
                .orElseGet(List::of);
    }

    private void apply(final ClientProtocolMapperEntity entity, final ProtocolMapperWriteDto write) {
        entity.setName(write.name());
        entity.setMapperType(write.mapperType());
        entity.setSource(blankToNull(write.source()));
        entity.setClaimName(write.claimName());
        entity.setAddToAccessToken(write.addToAccessToken() == null || write.addToAccessToken());
        entity.setAddToIdToken(write.addToIdToken() == null || write.addToIdToken());
    }

    private ProtocolMapperDto toDto(final ClientProtocolMapperEntity e) {
        return new ProtocolMapperDto(e.getMapperId(), e.getRealmId(), e.getClientId(), e.getName(),
                e.getMapperType(), e.getSource(), e.getClaimName(),
                Boolean.TRUE.equals(e.getAddToAccessToken()), Boolean.TRUE.equals(e.getAddToIdToken()));
    }

    private static String blankToDefault(final String realmId) {
        return realmId == null || realmId.isBlank() ? "master" : realmId;
    }

    private static String blankToNull(final String value) {
        return value == null || value.isBlank() ? null : value.trim();
    }
}
