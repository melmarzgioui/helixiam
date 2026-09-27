/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.notification.domain;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import org.hibernate.annotations.CreationTimestamp;

import java.util.Date;
import java.util.UUID;

@Entity
@Table(name = "notification_code")
@JsonIgnoreProperties(ignoreUnknown = true)
public class NotificationCode {
    @Id
    @JsonProperty
    @Column(name = "code")
    private String code;

    @JsonProperty
    @Column(name = "identifier")
    private String identifier;

    @JsonProperty
    @Column(name = "type")
    private String type;

    @CreationTimestamp
    @Column(name = "creation_date", updatable = false)
    private Date creationDate;

    // When the code stops working (V73); null on codes issued before it, see NotificationCodePolicy.
    @Column(name = "expires_at")
    private Date expiresAt;


    public NotificationCode() {
    }

    public NotificationCode(final String identifier, final String type) {
        this.code = UUID.randomUUID().toString();
        this.identifier = identifier;
        this.type = type;
    }

    public NotificationCode(final String identifier, final String code, final String type) {
        this.code = code;
        this.identifier = identifier;
        this.type = type;
    }

    public String getIdentifier() {
        return identifier;
    }

    public String getCode() {
        return code;
    }

    public String getType() {
        return type;
    }

    public Date getCreationDate() {
        return creationDate;
    }

    public void setCreationDate(final Date creationDate) {
        this.creationDate = creationDate;
    }

    /** When the code stops working, or null (issued before expiries were stored). */
    public Date getExpiresAt() {
        return expiresAt;
    }

    public void setExpiresAt(final Date expiresAt) {
        this.expiresAt = expiresAt;
    }
}
