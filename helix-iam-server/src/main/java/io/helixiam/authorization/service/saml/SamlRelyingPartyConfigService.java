/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.service.saml;

import io.helixiam.authorization.domain.saml.SamlRelyingPartyConfig;
import io.helixiam.authorization.domain.saml.SamlRelyingPartyEntity;
import io.helixiam.authorization.domain.saml.SamlSpOptions;
import io.helixiam.authorization.repository.saml.SamlRelyingPartyRepository;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Arrays;
import java.util.List;
import java.util.Optional;

/**
 * Helix IAM: owns the persisted, per-realm SAML2 relying parties (SPs) that the admin console writes
 * and the SAML IdP reads at request time. Mirrors the federation {@code IdentityProviderConfigService}.
 */
@Service
public class SamlRelyingPartyConfigService {

    private static final Logger LOG = LogManager.getLogger(SamlRelyingPartyConfigService.class);

    private final SamlRelyingPartyRepository repository;

    public SamlRelyingPartyConfigService(final SamlRelyingPartyRepository repository) {
        this.repository = repository;
    }

    /** Creates or updates the relying party for {@code (realmId, entityId)} (upsert by surrogate key). */
    @Transactional
    public SamlRelyingPartyConfig saveOrUpdate(final SamlRelyingPartyConfig config) {
        // Invariant guard: a relying party is meaningless without an entity ID + ACS URL.
        if (config.entityId() == null || config.entityId().isBlank()) {
            throw new IllegalArgumentException("Entity ID is required.");
        }
        if (config.assertionConsumerServiceUrl() == null || config.assertionConsumerServiceUrl().isBlank()) {
            throw new IllegalArgumentException("Assertion Consumer Service URL is required.");
        }
        final SamlRelyingPartyEntity entity = repository
                .findById(SamlRelyingPartyEntity.key(config.realmId(), config.entityId()))
                .orElseGet(SamlRelyingPartyEntity::new);
        entity.setId(SamlRelyingPartyEntity.key(config.realmId(), config.entityId()));
        entity.setRealmId(config.realmId());
        entity.setEntityId(config.entityId());
        entity.setAssertionConsumerServiceUrl(config.assertionConsumerServiceUrl());
        entity.setDefaultAuthnContextClassRef(config.defaultAuthnContextClassRef());
        entity.setSingleLogoutServiceUrl(config.singleLogoutServiceUrl());
        entity.setSigningCertificate(config.signingCertificate());
        entity.setEnabled(config.enabled());
        entity.setApplicationId(config.applicationId());
        applyOptions(entity, config.options());
        final SamlRelyingPartyEntity saved = repository.save(entity);
        LOG.debug("Saved SAML relying party {} for realm {}", config.entityId(), config.realmId());
        return toDto(saved);
    }

    /** All relying parties for a realm. */
    public List<SamlRelyingPartyConfig> list(final String realmId) {
        return repository.findAllByRealmId(realmId).stream().map(this::toDto).toList();
    }

    /** A single relying party by realm + entityId, when present. */
    public Optional<SamlRelyingPartyConfig> get(final String realmId, final String entityId) {
        return repository.findByRealmIdAndEntityId(realmId, entityId).map(this::toDto);
    }

    /** Removes a relying party; returns {@code false} if it did not exist. */
    @Transactional
    public boolean delete(final String realmId, final String entityId) {
        if (!repository.existsByRealmIdAndEntityId(realmId, entityId)) {
            return false;
        }
        repository.deleteByRealmIdAndEntityId(realmId, entityId);
        LOG.debug("Deleted SAML relying party {} for realm {}", entityId, realmId);
        return true;
    }

    private SamlRelyingPartyConfig toDto(final SamlRelyingPartyEntity entity) {
        return new SamlRelyingPartyConfig(entity.getRealmId(), entity.getEntityId(),
                entity.getAssertionConsumerServiceUrl(), entity.getDefaultAuthnContextClassRef(),
                entity.getSingleLogoutServiceUrl(), entity.getSigningCertificate(), entity.isEnabled(),
                entity.getApplicationId(), toOptions(entity));
    }

    /** Persist the advanced WSO2-class options (null block leaves every column null = IdP default). */
    private void applyOptions(final SamlRelyingPartyEntity entity, final SamlSpOptions o) {
        final SamlSpOptions opt = o == null ? new SamlSpOptions(null, null, null, null, null, null, null,
                null, null, null, null, null, null, null, null, null) : o;
        entity.setSignAssertion(opt.signAssertion());
        entity.setSignResponse(opt.signResponse());
        entity.setWantAuthnRequestsSigned(opt.wantAuthnRequestsSigned());
        entity.setWantLogoutRequestsSigned(opt.wantLogoutRequestsSigned());
        entity.setEncryptAssertion(opt.encryptAssertion());
        entity.setEncryptionCertificate(blankToNull(opt.encryptionCertificate()));
        entity.setSignatureAlgorithm(blankToNull(opt.signatureAlgorithm()));
        entity.setDigestAlgorithm(blankToNull(opt.digestAlgorithm()));
        entity.setNameIdFormat(blankToNull(opt.nameIdFormat()));
        entity.setIncludeAttributes(opt.includeAttributes());
        entity.setAdditionalAcsUrls(join(opt.additionalAcsUrls()));
        entity.setExtraAudiences(join(opt.extraAudiences()));
        entity.setExtraRecipients(join(opt.extraRecipients()));
        entity.setBackChannelSloEnabled(opt.backChannelSloEnabled());
        entity.setIdpInitiatedSsoEnabled(opt.idpInitiatedSsoEnabled());
        entity.setAssertionLifetimeSeconds(opt.assertionLifetimeSeconds());
    }

    private SamlSpOptions toOptions(final SamlRelyingPartyEntity e) {
        return new SamlSpOptions(e.getSignAssertion(), e.getSignResponse(), e.getWantAuthnRequestsSigned(),
                e.getWantLogoutRequestsSigned(), e.getEncryptAssertion(), e.getEncryptionCertificate(),
                e.getSignatureAlgorithm(), e.getDigestAlgorithm(), e.getNameIdFormat(), e.getIncludeAttributes(),
                split(e.getAdditionalAcsUrls()), split(e.getExtraAudiences()), split(e.getExtraRecipients()),
                e.getBackChannelSloEnabled(), e.getIdpInitiatedSsoEnabled(), e.getAssertionLifetimeSeconds());
    }

    /** URL/URI lists are stored newline-joined in a text column. */
    private static String join(final List<String> values) {
        if (values == null || values.isEmpty()) {
            return null;
        }
        return String.join("\n", values.stream().map(String::trim).filter(s -> !s.isEmpty()).toList());
    }

    private static List<String> split(final String text) {
        if (text == null || text.isBlank()) {
            return List.of();
        }
        return Arrays.stream(text.split("\\r?\\n")).map(String::trim).filter(s -> !s.isEmpty()).toList();
    }

    private static String blankToNull(final String s) {
        return s == null || s.isBlank() ? null : s;
    }
}
