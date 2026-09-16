/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.domain.messaging;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EntityListeners;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import org.hibernate.annotations.CreationTimestamp;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.util.Date;

/**
 * Helix IAM notifications (N6c): a registered push device token for a user, keyed by
 * {@code (realm_id, user_id, platform, token)}. {@code platform} is {@code FCM} (Android registration token)
 * or {@code APNS} (iOS device token); the mobile app registers it after enrollment so push approvals can be
 * delivered.
 */
@Entity
@Table(name = "device_push_token")
@EntityListeners(AuditingEntityListener.class)
public class DevicePushToken {

    @Id
    @JsonProperty
    @GeneratedValue(strategy = GenerationType.UUID)
    @Column(name = "id", updatable = false)
    private String id;

    @JsonProperty
    @Column(name = "realm_id")
    private String realmId;

    @JsonProperty
    @Column(name = "user_id")
    private String userId;

    /** {@code FCM} | {@code APNS}. */
    @JsonProperty
    @Column(name = "platform")
    private String platform;

    @JsonProperty
    @Column(name = "token", length = 512)
    private String token;

    @CreationTimestamp
    @Column(name = "creation_date", updatable = false)
    private Date creationDate;

    @LastModifiedDate
    @Column(name = "modify_date")
    private Date modifyDate;

    public String getId() { return id; }
    public void setId(final String id) { this.id = id; }
    public String getRealmId() { return realmId; }
    public void setRealmId(final String realmId) { this.realmId = realmId; }
    public String getUserId() { return userId; }
    public void setUserId(final String userId) { this.userId = userId; }
    public String getPlatform() { return platform; }
    public void setPlatform(final String platform) { this.platform = platform; }
    public String getToken() { return token; }
    public void setToken(final String token) { this.token = token; }
}
