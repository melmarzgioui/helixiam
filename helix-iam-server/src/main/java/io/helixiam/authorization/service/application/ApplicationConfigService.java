package io.helixiam.authorization.service.application;

import io.helixiam.authorization.domain.ServiceProviderOAuthClient;
import io.helixiam.authorization.domain.application.ApplicationConfig;
import io.helixiam.authorization.domain.application.ApplicationEntity;
import io.helixiam.authorization.domain.saml.SamlRelyingPartyEntity;
import io.helixiam.authorization.repository.ServiceProviderRepository;
import io.helixiam.authorization.repository.application.ApplicationRepository;
import io.helixiam.authorization.repository.saml.SamlRelyingPartyRepository;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Optional;

/**
 * Helix IAM: owns the persisted, per-realm Applications that the admin console writes and the
 * subject-claim + login-flow resolvers read. Mirrors {@code SamlRelyingPartyConfigService}.
 */
@Service
public class ApplicationConfigService {

    private static final Logger LOG = LogManager.getLogger(ApplicationConfigService.class);

    private final ApplicationRepository repository;
    private final ServiceProviderRepository serviceProviders;
    private final SamlRelyingPartyRepository relyingParties;

    public ApplicationConfigService(final ApplicationRepository repository,
                                    final ServiceProviderRepository serviceProviders,
                                    final SamlRelyingPartyRepository relyingParties) {
        this.repository = repository;
        this.serviceProviders = serviceProviders;
        this.relyingParties = relyingParties;
    }

    /** Creates or updates the application for {@code (realmId, name)} (upsert by surrogate key). */
    @Transactional
    public ApplicationConfig saveOrUpdate(final ApplicationConfig config) {
        // Invariant guard: an application is keyed by name, so it must be present.
        if (config.name() == null || config.name().isBlank()) {
            throw new IllegalArgumentException("Application name is required.");
        }
        final ApplicationEntity entity = repository
                .findById(ApplicationEntity.key(config.realmId(), config.name()))
                .orElseGet(ApplicationEntity::new);
        entity.setId(ApplicationEntity.key(config.realmId(), config.name()));
        entity.setRealmId(config.realmId());
        entity.setName(config.name());
        entity.setDisplayName(config.displayName());
        entity.setDescription(config.description());
        entity.setSubjectClaim(config.subjectClaim());
        entity.setAuthFlowAlias(config.authFlowAlias());
        entity.setEnabled(config.enabled());
        final ApplicationEntity saved = repository.save(entity);
        LOG.debug("Saved application {} for realm {}", config.name(), config.realmId());
        return toDto(saved);
    }

    /** All applications for a realm. */
    public List<ApplicationConfig> list(final String realmId) {
        return repository.findAllByRealmId(realmId).stream().map(this::toDto).toList();
    }

    /** A single application by realm + name, when present. */
    public Optional<ApplicationConfig> get(final String realmId, final String name) {
        return repository.findByRealmIdAndName(realmId, name).map(this::toDto);
    }

    /**
     * Removes an application and cascades to the protocols hanging below it: its linked OIDC client(s) are
     * soft-deleted (matching the OAuth client lifecycle, so the SAS hot path stops resolving them) and its
     * linked SAML relying part(y/ies) are hard-deleted. Returns {@code false} if the application did not exist.
     */
    @Transactional
    public boolean delete(final String realmId, final String name) {
        if (!repository.existsByRealmIdAndName(realmId, name)) {
            return false;
        }
        final String applicationId = ApplicationEntity.key(realmId, name);
        for (final ServiceProviderOAuthClient client : serviceProviders.findAllByApplicationIdAndDeleted(applicationId, false)) {
            client.setDeleted(true);
            serviceProviders.save(client);
            LOG.debug("Cascade: soft-deleted OIDC client {} with application {}", client.getClientId(), name);
        }
        for (final SamlRelyingPartyEntity rp : relyingParties.findAllByApplicationId(applicationId)) {
            relyingParties.delete(rp);
            LOG.debug("Cascade: deleted SAML relying party {} with application {}", rp.getEntityId(), name);
        }
        repository.deleteByRealmIdAndName(realmId, name);
        LOG.debug("Deleted application {} for realm {}", name, realmId);
        return true;
    }

    private ApplicationConfig toDto(final ApplicationEntity entity) {
        return new ApplicationConfig(entity.getRealmId(), entity.getName(), entity.getDescription(),
                entity.getSubjectClaim(), entity.getAuthFlowAlias(), entity.isEnabled(), entity.getDisplayName());
    }
}
