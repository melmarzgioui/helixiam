package io.helixiam.authorization.service;

import io.helixiam.authorization.domain.realm.RealmConfig;
import io.helixiam.authorization.repository.realm.RealmConfigRepository;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.function.Consumer;

/**
 * Realm configuration service (Helix IAM E1.3).
 *
 * <p>A realm maps 1:1 to a tenant ({@code realmId == tenantId}). This service owns the
 * per-realm settings ({@link RealmConfig}); a realm row is created with platform defaults
 * whenever a tenant is created (see {@code TenantService.create}). Reads fall back to
 * transient defaults so the absence of a row never breaks token issuance — the store can
 * back-fill lazily for tenants that pre-date this table.
 */
@Service
public class RealmService {

    private static final Logger LOG = LogManager.getLogger(RealmService.class);

    private final RealmConfigRepository realmConfigRepository;

    @Autowired
    public RealmService(final RealmConfigRepository realmConfigRepository) {
        this.realmConfigRepository = realmConfigRepository;
    }

    /**
     * Returns the persisted realm config, or platform defaults (transient) when none exists.
     */
    public RealmConfig getOrDefault(final String realmId) {
        return realmConfigRepository.findById(realmId).orElseGet(() -> RealmConfig.defaults(realmId));
    }

    /** Whether a realm config row exists for the given realm id. */
    public boolean exists(final String realmId) {
        return realmConfigRepository.existsById(realmId);
    }

    /**
     * Creates a realm config with platform defaults for the given realm id, unless one
     * already exists. Idempotent — returns the existing config when present.
     */
    public RealmConfig createIfAbsent(final String realmId, final String displayName) {
        return realmConfigRepository.findById(realmId).orElseGet(() -> {
            final RealmConfig config = RealmConfig.defaults(realmId);
            config.setDisplayName(displayName);
            final RealmConfig saved = realmConfigRepository.save(config);
            LOG.debug("Created realm config for realm {}", realmId);
            return saved;
        });
    }

    /** Persists realm config changes. */
    public RealmConfig save(final RealmConfig realmConfig) {
        return realmConfigRepository.save(realmConfig);
    }

    /** Lists all configured realms (admin). */
    public List<RealmConfig> list() {
        return realmConfigRepository.findAll();
    }

    /**
     * Applies a mutation to an existing realm's config and persists it (admin update).
     * No-op (returns {@code null}) if the realm does not exist.
     */
    public RealmConfig update(final String realmId, final Consumer<RealmConfig> mutator) {
        return realmConfigRepository.findById(realmId)
                .map(config -> {
                    mutator.accept(config);
                    final RealmConfig saved = realmConfigRepository.save(config);
                    LOG.debug("Updated realm config {}", realmId);
                    return saved;
                })
                .orElse(null);
    }

    /**
     * Ensures the bootstrap administration realm ("master") exists. Called at startup so
     * a fresh deployment always has the realm that administers all others.
     */
    public RealmConfig ensureAdminRealm() {
        return createIfAbsent(RealmConfig.ADMIN_REALM_ID, "Master");
    }
}
