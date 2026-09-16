/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.domain.federation;

import jakarta.persistence.Column;
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
 * in {@code config_json} (a serialised map) to keep the table stable as provider types grow.
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
