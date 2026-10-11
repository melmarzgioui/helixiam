/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.domain.federation;

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
 * Helix IAM E8.1: a persisted identity-provider configuration, partitioned per realm. The id is
 * {@code realmId|alias}, so an alias is unique within a realm. The protocol-specific settings live
 * in {@code config_json} (a serialised map) to keep the table stable as provider types grow. Secrets
 * ({@code ProviderSecretKeys}) are never kept there: they live in {@code secret_json}, a serialised map encrypted at
 * rest with {@code DB_ENCRYPTION} (Task 4, security).
 */
@Entity
@Table(name = "identity_provider")
@EntityListeners(AuditingEntityListener.class)
public class IdentityProviderEntity {

    @Id
    @Column(name = "id")
    private String id;

    @Column(name = "realm_id")
    private String realmId;

    @Column(name = "alias")
    private String alias;

    @Column(name = "protocol")
    private String protocol;

    @Column(name = "display_name")
    private String displayName;

    @Column(name = "config_json", columnDefinition = "text")
    private String configJson;

    @Convert(converter = AttributeEncryption.class)
    @Column(name = "secret_json", columnDefinition = "text")
    private String secretJson;

    @Column(name = "enabled")
    private boolean enabled = true;

    @CreationTimestamp
    @Column(name = "creation_date", updatable = false)
    private Date creationDate;

    @LastModifiedDate
    @Column(name = "modify_date")
    private Date modifyDate;

    /** The surrogate primary key for a (realm, alias) pair. */
    public static String key(final String realmId, final String alias) {
        return realmId + "|" + alias;
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

    public String getAlias() {
        return alias;
    }

    public void setAlias(final String alias) {
        this.alias = alias;
    }

    public String getProtocol() {
        return protocol;
    }

    public void setProtocol(final String protocol) {
        this.protocol = protocol;
    }

    public String getDisplayName() {
        return displayName;
    }

    public void setDisplayName(final String displayName) {
        this.displayName = displayName;
    }

    public String getConfigJson() {
        return configJson;
    }

    public void setConfigJson(final String configJson) {
        this.configJson = configJson;
    }

    public String getSecretJson() {
        return secretJson;
    }

    public void setSecretJson(final String secretJson) {
        this.secretJson = secretJson;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(final boolean enabled) {
        this.enabled = enabled;
    }

    public Date getCreationDate() {
        return creationDate;
    }

    public Date getModifyDate() {
        return modifyDate;
    }
}
