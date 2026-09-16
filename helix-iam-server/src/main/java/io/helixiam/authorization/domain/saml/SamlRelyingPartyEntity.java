/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.domain.saml;

import io.helixiam.persistence.security.AttributeEncryption;
import jakarta.persistence.Column;
import jakarta.persistence.Convert;
import jakarta.persistence.Entity;
import jakarta.persistence.EntityListeners;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import org.hibernate.annotations.CreationTimestamp;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.util.Date;

/**
 * Helix IAM: a persisted SAML2 relying party (service provider), partitioned per realm. The id is
 * {@code realmId|entityId}, so an SP entity id is unique within a realm. Managed via the admin API +
 * console and read by the SAML IdP at request time — the static {@code helix.idp.saml.relyingParties}
 * config is only a fallback. Mirrors the federation identity-provider config (E8.1).
 */
@Entity
@Table(name = "saml_relying_party")
@EntityListeners(AuditingEntityListener.class)
public class SamlRelyingPartyEntity {

    @Id
    @Column(name = "id")
    private String id;

    @Column(name = "realm_id")
    private String realmId;

    @Column(name = "entity_id")
    private String entityId;

    @Column(name = "assertion_consumer_service_url")
    private String assertionConsumerServiceUrl;

    @Column(name = "default_authn_context_class_ref")
    private String defaultAuthnContextClassRef;

    @Column(name = "single_logout_service_url")
    private String singleLogoutServiceUrl;

    // The SP's signing cert is sensitive material; encrypt it at rest like other secrets.
    @Convert(converter = AttributeEncryption.class)
    @Column(name = "signing_certificate", columnDefinition = "text")
    private String signingCertificate;

    @Column(name = "enabled")
    private boolean enabled = true;

    // Helix IAM (Application model): the parent Application (realmId|name) this SAML SP hangs below.
    // null = standalone RP (legacy). When set, the app's shared claims + login flow apply.
    @Column(name = "application_id")
    private String applicationId;

    // --- WSO2-class advanced SAML options (all nullable; null = IdP default, applied at assertion time) ---
    @Column(name = "sign_assertion")
    private Boolean signAssertion;
    @Column(name = "sign_response")
    private Boolean signResponse;
    @Column(name = "want_authn_requests_signed")
    private Boolean wantAuthnRequestsSigned;
    @Column(name = "want_logout_requests_signed")
    private Boolean wantLogoutRequestsSigned;
    @Column(name = "encrypt_assertion")
    private Boolean encryptAssertion;
    @Convert(converter = AttributeEncryption.class)
    @Column(name = "encryption_certificate", columnDefinition = "text")
    private String encryptionCertificate;
    @Column(name = "signature_algorithm")
    private String signatureAlgorithm;
    @Column(name = "digest_algorithm")
    private String digestAlgorithm;
    @Column(name = "name_id_format")
    private String nameIdFormat;
    @Column(name = "include_attributes")
    private Boolean includeAttributes;
    @Column(name = "additional_acs_urls", columnDefinition = "text")
    private String additionalAcsUrls;
    @Column(name = "extra_audiences", columnDefinition = "text")
    private String extraAudiences;
    @Column(name = "extra_recipients", columnDefinition = "text")
    private String extraRecipients;
    @Column(name = "back_channel_slo_enabled")
    private Boolean backChannelSloEnabled;
    @Column(name = "idp_initiated_sso_enabled")
    private Boolean idpInitiatedSsoEnabled;
    @Column(name = "assertion_lifetime_seconds")
    private Integer assertionLifetimeSeconds;

    @CreationTimestamp
    @Column(name = "creation_date", updatable = false)
    private Date creationDate;

    @LastModifiedDate
    @Column(name = "modify_date")
    private Date modifyDate;

    /** The surrogate primary key for a (realm, entityId) pair. */
    public static String key(final String realmId, final String entityId) {
        return realmId + "|" + entityId;
    }

    public String getId() {
        return id;
    }

    public void setId(final String id) {
        this.id = id;
    }

    public String getRealmId() {
        return realmId;
    }

    public void setRealmId(final String realmId) {
        this.realmId = realmId;
    }

    public String getEntityId() {
        return entityId;
    }

    public void setEntityId(final String entityId) {
        this.entityId = entityId;
    }

    public String getAssertionConsumerServiceUrl() {
        return assertionConsumerServiceUrl;
    }

    public void setAssertionConsumerServiceUrl(final String assertionConsumerServiceUrl) {
        this.assertionConsumerServiceUrl = assertionConsumerServiceUrl;
    }

    public String getDefaultAuthnContextClassRef() {
        return defaultAuthnContextClassRef;
    }

    public void setDefaultAuthnContextClassRef(final String defaultAuthnContextClassRef) {
        this.defaultAuthnContextClassRef = defaultAuthnContextClassRef;
    }

    public String getSingleLogoutServiceUrl() {
        return singleLogoutServiceUrl;
    }

    public void setSingleLogoutServiceUrl(final String singleLogoutServiceUrl) {
        this.singleLogoutServiceUrl = singleLogoutServiceUrl;
    }

    public String getSigningCertificate() {
        return signingCertificate;
    }

    public void setSigningCertificate(final String signingCertificate) {
        this.signingCertificate = signingCertificate;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(final boolean enabled) {
        this.enabled = enabled;
    }

    public String getApplicationId() {
        return applicationId;
    }

    public void setApplicationId(final String applicationId) {
        this.applicationId = applicationId;
    }

    public Boolean getSignAssertion() { return signAssertion; }
    public void setSignAssertion(final Boolean v) { this.signAssertion = v; }
    public Boolean getSignResponse() { return signResponse; }
    public void setSignResponse(final Boolean v) { this.signResponse = v; }
    public Boolean getWantAuthnRequestsSigned() { return wantAuthnRequestsSigned; }
    public void setWantAuthnRequestsSigned(final Boolean v) { this.wantAuthnRequestsSigned = v; }
    public Boolean getWantLogoutRequestsSigned() { return wantLogoutRequestsSigned; }
    public void setWantLogoutRequestsSigned(final Boolean v) { this.wantLogoutRequestsSigned = v; }
    public Boolean getEncryptAssertion() { return encryptAssertion; }
    public void setEncryptAssertion(final Boolean v) { this.encryptAssertion = v; }
    public String getEncryptionCertificate() { return encryptionCertificate; }
    public void setEncryptionCertificate(final String v) { this.encryptionCertificate = v; }
    public String getSignatureAlgorithm() { return signatureAlgorithm; }
    public void setSignatureAlgorithm(final String v) { this.signatureAlgorithm = v; }
    public String getDigestAlgorithm() { return digestAlgorithm; }
    public void setDigestAlgorithm(final String v) { this.digestAlgorithm = v; }
    public String getNameIdFormat() { return nameIdFormat; }
    public void setNameIdFormat(final String v) { this.nameIdFormat = v; }
    public Boolean getIncludeAttributes() { return includeAttributes; }
    public void setIncludeAttributes(final Boolean v) { this.includeAttributes = v; }
    public String getAdditionalAcsUrls() { return additionalAcsUrls; }
    public void setAdditionalAcsUrls(final String v) { this.additionalAcsUrls = v; }
    public String getExtraAudiences() { return extraAudiences; }
    public void setExtraAudiences(final String v) { this.extraAudiences = v; }
    public String getExtraRecipients() { return extraRecipients; }
    public void setExtraRecipients(final String v) { this.extraRecipients = v; }
    public Boolean getBackChannelSloEnabled() { return backChannelSloEnabled; }
    public void setBackChannelSloEnabled(final Boolean v) { this.backChannelSloEnabled = v; }
    public Boolean getIdpInitiatedSsoEnabled() { return idpInitiatedSsoEnabled; }
    public void setIdpInitiatedSsoEnabled(final Boolean v) { this.idpInitiatedSsoEnabled = v; }
    public Integer getAssertionLifetimeSeconds() { return assertionLifetimeSeconds; }
    public void setAssertionLifetimeSeconds(final Integer v) { this.assertionLifetimeSeconds = v; }

    public Date getCreationDate() {
        return creationDate;
    }

    public Date getModifyDate() {
        return modifyDate;
    }
}
