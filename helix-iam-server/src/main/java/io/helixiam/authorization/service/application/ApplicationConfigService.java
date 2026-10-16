/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.service.application;

import io.helixiam.authorization.domain.ServiceProviderOAuthClient;
import io.helixiam.authorization.domain.application.ApplicationConfig;
import io.helixiam.authorization.domain.application.ApplicationEntity;
import io.helixiam.authorization.domain.saml.SamlRelyingPartyEntity;
import io.helixiam.authorization.repository.ServiceProviderRepository;
import io.helixiam.authorization.repository.application.ApplicationRepository;
import io.helixiam.authorization.repository.saml.SamlRelyingPartyRepository;
import io.helixiam.common.log.LogSafe;
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

    private io.helixiam.authorization.service.adminrbac.PrivilegedPrincipalGuard privileged;

    /** Round 6: guards the Applications of the built-in sign-in clients (absent in slim unit-test wiring). */
    @org.springframework.beans.factory.annotation.Autowired(required = false)
    public void setPrivilegedPrincipalGuard(
            final io.helixiam.authorization.service.adminrbac.PrivilegedPrincipalGuard privileged) {
        this.privileged = privileged;
    }

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
        final Optional<ApplicationEntity> stored = repository.findById(ApplicationEntity.key(config.realmId(), config.name()));
        if (privileged != null && stored.isPresent() && !onlyCosmetic(stored.get(), config)) {
            // Round 6: the subject claim, flow and enabled flag of a sign-in client's Application decide how
            // administrators sign in; display name and description stay open to client managers.
            privileged.requireMayChangeApplication(config.realmId(), config.name(),
                    "Changing application " + config.name());
        }
        final ApplicationEntity entity = stored.orElseGet(ApplicationEntity::new);
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
        if (privileged != null) {
            // Round 6: the cascade soft-deletes the child clients, so it needs what deleting each of them needs.
            privileged.requireMayChangeApplication(realmId, name, "Deleting application " + name);
            for (final ServiceProviderOAuthClient child : serviceProviders.findAllByApplicationIdAndDeleted(applicationId, false)) {
                privileged.requireMayActOnClient(realmId, child.getClientId(), "Deleting application " + name);
            }
        }
        for (final ServiceProviderOAuthClient client : serviceProviders.findAllByApplicationIdAndDeleted(applicationId, false)) {
            client.setDeleted(true);
            serviceProviders.save(client);
            LOG.debug("Cascade: soft-deleted OIDC client {} with application {}",
                    LogSafe.sanitize(client.getClientId()), LogSafe.sanitize(name));
        }
        for (final SamlRelyingPartyEntity rp : relyingParties.findAllByApplicationId(applicationId)) {
            relyingParties.delete(rp);
            LOG.debug("Cascade: deleted SAML relying party {} with application {}",
                    LogSafe.sanitize(rp.getEntityId()), LogSafe.sanitize(name));
        }
        repository.deleteByRealmIdAndName(realmId, name);
        LOG.debug("Deleted application {} for realm {}", LogSafe.sanitize(name), LogSafe.sanitize(realmId));
        return true;
    }

    /** Whether the write changes only the display name or description of the stored application. */
    static boolean onlyCosmetic(final ApplicationEntity stored, final ApplicationConfig config) {
        return java.util.Objects.equals(blankToNull(stored.getSubjectClaim()), blankToNull(config.subjectClaim()))
                && java.util.Objects.equals(blankToNull(stored.getAuthFlowAlias()), blankToNull(config.authFlowAlias()))
                && stored.isEnabled() == config.enabled();
    }

    private static String blankToNull(final String s) {
        return s == null || s.isBlank() ? null : s;
    }

    private ApplicationConfig toDto(final ApplicationEntity entity) {
        return new ApplicationConfig(entity.getRealmId(), entity.getName(), entity.getDescription(),
                entity.getSubjectClaim(), entity.getAuthFlowAlias(), entity.isEnabled(), entity.getDisplayName());
    }
}
