package group.mfnr.authorization.service.federation;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import group.mfnr.authorization.domain.federation.IdentityProviderConfig;
import group.mfnr.authorization.domain.federation.IdentityProviderEntity;
import group.mfnr.authorization.repository.federation.IdentityProviderConfigRepository;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Helix IAM E8.1: owns the persisted, per-realm identity-provider configs that the admin console
 * (E8.2) writes and the federation registry (E8.3) reads. The protocol-specific settings are stored
 * as a JSON map so the schema stays stable as provider types grow.
 */
@Service
public class IdentityProviderConfigService {

    private static final Logger LOG = LogManager.getLogger(IdentityProviderConfigService.class);
    private static final TypeReference<Map<String, String>> CONFIG_TYPE = new TypeReference<>() {
    };

    private final IdentityProviderConfigRepository repository;
    private final ObjectMapper objectMapper = new ObjectMapper();

    @Autowired
    public IdentityProviderConfigService(final IdentityProviderConfigRepository repository) {
        this.repository = repository;
    }

    /** Creates or updates the config for {@code (realmId, alias)} (upsert by surrogate key). */
    @Transactional
    public IdentityProviderConfig saveOrUpdate(final IdentityProviderConfig config) {
        final IdentityProviderEntity entity = repository
                .findById(IdentityProviderEntity.key(config.realmId(), config.alias()))
                .orElseGet(IdentityProviderEntity::new);
        entity.setId(IdentityProviderEntity.key(config.realmId(), config.alias()));
        entity.setRealmId(config.realmId());
        entity.setAlias(config.alias());
        entity.setProtocol(config.protocol());
        entity.setDisplayName(config.displayName());
        entity.setEnabled(config.enabled());
        entity.setConfigJson(writeConfig(config.config()));
        final IdentityProviderEntity saved = repository.save(entity);
        LOG.debug("Saved identity-provider config {} for realm {}", config.alias(), config.realmId());
        return toDto(saved);
    }

    /** All identity-provider configs for a realm. */
    public List<IdentityProviderConfig> list(final String realmId) {
        return repository.findAllByRealmId(realmId).stream().map(this::toDto).toList();
    }

    /** A single config by realm + alias, when present. */
    public Optional<IdentityProviderConfig> get(final String realmId, final String alias) {
        return repository.findByRealmIdAndAlias(realmId, alias).map(this::toDto);
    }

    /** Removes a config; returns {@code false} if it did not exist. */
    @Transactional
    public boolean delete(final String realmId, final String alias) {
        if (!repository.existsByRealmIdAndAlias(realmId, alias)) {
            return false;
        }
        repository.deleteByRealmIdAndAlias(realmId, alias);
        LOG.debug("Deleted identity-provider config {} for realm {}", alias, realmId);
        return true;
    }

    private IdentityProviderConfig toDto(final IdentityProviderEntity entity) {
        return new IdentityProviderConfig(entity.getRealmId(), entity.getAlias(), entity.getProtocol(),
                entity.getDisplayName(), entity.isEnabled(), readConfig(entity.getConfigJson()));
    }

    private String writeConfig(final Map<String, String> config) {
        try {
            return objectMapper.writeValueAsString(config == null ? Map.of() : config);
        } catch (final Exception e) {
            throw new IllegalArgumentException("Could not serialise identity-provider config", e);
        }
    }

    private Map<String, String> readConfig(final String json) {
        if (json == null || json.isBlank()) {
            return Map.of();
        }
        try {
            return objectMapper.readValue(json, CONFIG_TYPE);
        } catch (final Exception e) {
            throw new IllegalStateException("Could not deserialise identity-provider config", e);
        }
    }
}
