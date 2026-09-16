/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.domain.device;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import org.hibernate.annotations.CreationTimestamp;

import java.util.Date;

/**
 * Helix IAM E4.1: an enrolled device's signing credential (VeridPay-style device factor). Holds the
 * device's non-exportable P-256 public key (SPKI, base64) plus the platform whose attestation
 * vouched for it and whether the key is biometric-gated. Device assertions are verified against this
 * key (ES256) over single-use server challenges, so no shared secret is stored.
 */
@Entity
@Table(name = "device_credential")
public class DeviceCredentialEntity {

    @Id
    @Column(name = "device_id")
    private String deviceId;

    @Column(name = "user_id")
    private String userId;

    /** Device public key as X.509 SubjectPublicKeyInfo, base64-encoded. */
    @Column(name = "public_key")
    private String publicKey;

    /** Attestation platform that vouched for the key: "none", "apple-app-attest", "android-key". */
    @Column(name = "platform")
    private String platform;

    /** Whether the device key is gated behind a biometric (Face/Touch ID, BiometricPrompt). */
    @Column(name = "biometric")
    private boolean biometric;

    @CreationTimestamp
    @Column(name = "creation_date", updatable = false)
    private Date creationDate;

    @Column(name = "last_used_date")
    private Date lastUsedDate;

    public DeviceCredentialEntity() {
    }

    public DeviceCredentialEntity(final String deviceId, final String userId, final String publicKey,
                                  final String platform, final boolean biometric) {
        this.deviceId = deviceId;
        this.userId = userId;
        this.publicKey = publicKey;
        this.platform = platform;
        this.biometric = biometric;
    }

    public String getDeviceId() {
        return deviceId;
    }

    public String getUserId() {
        return userId;
    }

    public String getPublicKey() {
        return publicKey;
    }

    public String getPlatform() {
        return platform;
    }

    public boolean isBiometric() {
        return biometric;
    }

    public Date getCreationDate() {
        return creationDate;
    }

    public Date getLastUsedDate() {
        return lastUsedDate;
    }

    public void setLastUsedDate(final Date lastUsedDate) {
        this.lastUsedDate = lastUsedDate;
    }
}
