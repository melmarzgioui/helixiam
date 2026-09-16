package io.helixiam.authorization.service.scim;

import io.helixiam.authorization.domain.scim.ScimTarget;
import io.helixiam.authorization.domain.scim.ScimTargetDto;
import io.helixiam.authorization.repository.scim.ScimTargetRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.UUID;

/**
 * Helix IAM B7: CRUD + active-lookup for per-realm outbound SCIM provisioning targets. The bearer
 * {@code token} is write-only from the console's perspective — a blank token on update preserves the
 * stored one (so editing other fields never wipes the credential).
 */
@Service
public class ScimTargetAdminService {

    private final ScimTargetRepository repository;

    public ScimTargetAdminService(final ScimTargetRepository repository) {
        this.repository = repository;
    }

    @Transactional(readOnly = true)
    public List<ScimTargetDto> list(final String realmId) {
        return repository.findAllByRealmIdOrderByCreationDateAsc(realmId).stream().map(ScimTargetDto::from).toList();
    }

    /** Enabled targets for a realm — what the publisher's dispatcher pushes user lifecycle changes to. */
    @Transactional(readOnly = true)
    public List<ScimTargetDto> active(final String realmId) {
        return repository.findAllByRealmIdAndEnabledTrue(realmId).stream().map(ScimTargetDto::from).toList();
    }

    @Transactional
    public ScimTargetDto save(final ScimTargetDto dto) {
        final ScimTarget entity = dto.id() == null || dto.id().isBlank()
                ? newEntity(dto.realmId())
                : repository.findById(dto.id()).orElseGet(() -> newEntity(dto.realmId()));
        entity.setRealmId(dto.realmId());
        entity.setName(blankToNull(dto.name()));
        entity.setBaseUrl(dto.baseUrl() == null ? null : dto.baseUrl().trim());
        entity.setEventTypes(dto.eventTypes() == null ? "" : dto.eventTypes().trim());
        entity.setEnabled(dto.enabled());
        // Token is write-only: only overwrite when a new non-blank value is supplied.
        if (dto.token() != null && !dto.token().isBlank()) {
            entity.setToken(dto.token().trim());
        }
        return ScimTargetDto.from(repository.save(entity));
    }

    @Transactional
    public boolean delete(final String realmId, final String id) {
        return repository.findById(id)
                .filter(t -> realmId.equals(t.getRealmId()))
                .map(t -> {
                    repository.delete(t);
                    return true;
                }).orElse(false);
    }

    private ScimTarget newEntity(final String realmId) {
        final ScimTarget t = new ScimTarget();
        t.setId(UUID.randomUUID().toString());
        t.setRealmId(realmId);
        return t;
    }

    private static String blankToNull(final String v) {
        return v == null || v.isBlank() ? null : v.trim();
    }
}
