/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.service.federation;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.helixiam.authorization.domain.federation.IdentityProviderConfig;
import io.helixiam.authorization.domain.federation.IdentityProviderEntity;
import io.helixiam.authorization.federation.ProviderSecretKeys;
import io.helixiam.authorization.repository.federation.IdentityProviderConfigRepository;
import io.helixiam.common.log.LogSafe;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Supplier;

/**
 * Helix IAM E8.1: owns the persisted, per-realm identity-provider configs that the admin console
 * (E8.2) writes and the federation registry (E8.3) reads. The protocol-specific settings are stored
 * as a JSON map so the schema stays stable as provider types grow.
 *
 * <p>Task 4 (security): secrets ({@link ProviderSecretKeys}) are split off into {@code secret_json} (encrypted at rest
 * by the entity's converter) and merged back on read, so the runtime ({@code FederationProviderFactory.fromStored})
 * sees one map. Writes are write-only for secrets: absent / blank keeps, a value replaces, {@code clear<Key>=true}
 * removes. A legacy secret still in {@code config_json} is read as a secret and moved on the next save.
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
        final Map<String, String> secrets = new LinkedHashMap<>(storedSecrets(entity));
        // A protocol change drops the stored secrets the new protocol does not use (they would stay, encrypted, unread).
        final String previousProtocol = entity.getProtocol();
        secrets.keySet().removeIf(key -> !ProviderSecretKeys.keepsStoredSecret(previousProtocol, config.protocol(), key));
        entity.setId(IdentityProviderEntity.key(config.realmId(), config.alias()));
        entity.setRealmId(config.realmId());
        entity.setAlias(config.alias());
        entity.setProtocol(config.protocol());
        entity.setDisplayName(config.displayName());
        entity.setEnabled(config.enabled());
        final Map<String, String> incoming = config.config() == null ? Map.of() : config.config();
        final ProviderSecretKeys.Split split = ProviderSecretKeys.split(config.protocol(), incoming);
        for (final String key : ProviderSecretKeys.allKeys()) {
            if (split.secrets().containsKey(key)) {
                secrets.put(key, split.secrets().get(key));
            } else if (ProviderSecretKeys.clears(incoming, key)) {
                secrets.remove(key);
            }
        }
        entity.setConfigJson(writeConfig(split.plain()));
        entity.setSecretJson(secrets.isEmpty() ? null : writeConfig(secrets));
        final IdentityProviderEntity saved = repository.save(entity);
        LOG.debug("Saved identity-provider config {} for realm {}",
                LogSafe.sanitize(config.alias()), LogSafe.sanitize(config.realmId()));
        return toDto(saved);
    }

    /** All readable identity-provider configs for a realm (an unreadable row is logged by id and skipped). */
    public List<IdentityProviderConfig> list(final String realmId) {
        return readable(() -> repository.findAllByRealmId(realmId), () -> repository.findIdsByRealmId(realmId));
    }

    /** All readable identity-provider configs of every realm (an unreadable row is logged by id and skipped). */
    public List<IdentityProviderConfig> listAll() {
        return readable(repository::findAll, repository::findAllIds);
    }

    /**
     * Final review m3: one row whose secrets cannot be read (a wrong {@code DB_ENCRYPTION} key, a corrupt value) must not
     * take every other provider down with it: those are mapped one by one, and when loading the set itself fails (the
     * entity converter refusing a value fails the whole query) the rows are loaded one id at a time instead.
     */
    private List<IdentityProviderConfig> readable(final Supplier<List<IdentityProviderEntity>> all,
                                                  final Supplier<List<String>> ids) {
        List<IdentityProviderEntity> entities;
        try {
            entities = all.get();
        } catch (final RuntimeException e) {
            LOG.warn("Identity-provider configs could not be loaded together ({}); loading them one by one",
                    e.getClass().getSimpleName());
            entities = new ArrayList<>();
            for (final String id : ids.get()) {
                try {
                    repository.findById(id).ifPresent(entities::add);
                } catch (final RuntimeException rowFailure) {
                    skip(id, rowFailure);
                }
            }
        }
        final List<IdentityProviderConfig> configs = new ArrayList<>();
        for (final IdentityProviderEntity entity : entities) {
            try {
                configs.add(toDto(entity));
            } catch (final RuntimeException e) {
                skip(entity.getId(), e);
            }
        }
        return configs;
    }

    private static void skip(final String id, final RuntimeException e) {
        // the id only: the exception text could quote the stored value
        LOG.warn("Skipping identity-provider config {}: it cannot be read ({}). Check DB_ENCRYPTION, then re-save or "
                + "delete it.", LogSafe.sanitize(id), e.getClass().getSimpleName());
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
        LOG.debug("Deleted identity-provider config {} for realm {}",
                LogSafe.sanitize(alias), LogSafe.sanitize(realmId));
        return true;
    }

    private IdentityProviderConfig toDto(final IdentityProviderEntity entity) {
        final Map<String, String> merged = new LinkedHashMap<>(readConfig(entity.getConfigJson()));
        merged.putAll(readConfig(entity.getSecretJson()));
        return new IdentityProviderConfig(entity.getRealmId(), entity.getAlias(), entity.getProtocol(),
                entity.getDisplayName(), entity.isEnabled(), merged);
    }

    /** The entity's current secrets: {@code secret_json}, plus any legacy secret still in {@code config_json}. */
    private Map<String, String> storedSecrets(final IdentityProviderEntity entity) {
        if (entity.getId() == null) {
            return Map.of();
        }
        final Map<String, String> secrets = new LinkedHashMap<>(
                ProviderSecretKeys.split(entity.getProtocol(), readConfig(entity.getConfigJson())).secrets());
        secrets.putAll(readConfig(entity.getSecretJson()));
        return secrets;
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
