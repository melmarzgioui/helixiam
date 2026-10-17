/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.domain.realm;

import io.helixiam.persistence.security.AttributeEncryption;
import jakarta.persistence.Column;
import jakarta.persistence.Convert;
import jakarta.persistence.Entity;
import jakarta.persistence.EntityListeners;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import org.hibernate.annotations.CreationTimestamp;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.util.Date;

/**
 * A per-realm JWT signing key (Helix IAM E1.4).
 *
 * <p>The private key is stored Base64-encoded and <b>encrypted at rest</b> via
 * {@link AttributeEncryption}; the public key is plaintext. Keys move PENDING → ACTIVE → ROTATED →
 * RETIRED: PENDING is published (JWKS, SAML metadata) but does not sign, ACTIVE signs new tokens, ROTATED stays
 * published so tokens signed before still verify (zero-downtime), RETIRED is dropped. {@code algorithm} is the JWS
 * algorithm (RS256 or ES256; rc.11 rows said {@code RSA}, see {@link #getJwsAlgorithm()}). An imported or CA-signed
 * key carries its certificate chain (PEM, leaf first).
 */
@Entity
@Table(name = "realm_key")
@EntityListeners(AuditingEntityListener.class)
public class RealmKey {

    public enum Status { PENDING, ACTIVE, ROTATED, RETIRED }

    /** Where a key came from. */
    public enum Source { GENERATED, IMPORTED, CSR }

    @Id
    @Column(name = "key_id")
    private String keyId;

    @Column(name = "realm_id")
    private String realmId;

    @Column(name = "algorithm")
    private String algorithm = "RS256";

    @Column(name = "public_key")
    private String publicKey;

    @Convert(converter = AttributeEncryption.class)
    @Column(name = "private_key")
    private String privateKey;

    @Column(name = "status")
    private String status = Status.ACTIVE.name();

    @CreationTimestamp
    @Column(name = "creation_date", updatable = false)
    private Date creationDate;

    @Column(name = "rotated_date")
    private Date rotatedDate;

    @Column(name = "certificate_chain_pem")
    private String certificateChainPem;

    @Column(name = "csr_pem")
    private String csrPem;

    @Column(name = "source")
    private String source = Source.GENERATED.name();

    @Column(name = "activated_date")
    private Date activatedDate;

    @Column(name = "expiry_warned_on")
    private java.time.LocalDate expiryWarnedOn;

    public RealmKey() {
    }

    public RealmKey(final String keyId, final String realmId, final String algorithm,
                    final String publicKey, final String privateKey) {
        this.keyId = keyId;
        this.realmId = realmId;
        this.algorithm = algorithm;
        this.publicKey = publicKey;
        this.privateKey = privateKey;
        this.status = Status.ACTIVE.name();
    }

    public String getKeyId() {
        return keyId;
    }

    public String getRealmId() {
        return realmId;
    }

    public String getAlgorithm() {
        return algorithm;
    }

    public String getPublicKey() {
        return publicKey;
    }

    public String getPrivateKey() {
        return privateKey;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(final Status status) {
        this.status = status.name();
    }

    public Date getCreationDate() {
        return creationDate;
    }

    public Date getRotatedDate() {
        return rotatedDate;
    }

    public void setRotatedDate(final Date rotatedDate) {
        this.rotatedDate = rotatedDate;
    }

    public boolean isActive() {
        return Status.ACTIVE.name().equals(status);
    }

    public boolean hasStatus(final Status s) {
        return s.name().equals(status);
    }

    /** The JWS algorithm: a legacy {@code RSA} row is RS256. */
    public String getJwsAlgorithm() {
        return io.helixiam.authorization.service.key.RealmKeyMaterial.normalizeAlgorithm(algorithm);
    }

    public void setAlgorithm(final String algorithm) {
        this.algorithm = algorithm;
    }

    public String getCertificateChainPem() {
        return certificateChainPem;
    }

    public void setCertificateChainPem(final String certificateChainPem) {
        this.certificateChainPem = certificateChainPem;
    }

    public String getCsrPem() {
        return csrPem;
    }

    public void setCsrPem(final String csrPem) {
        this.csrPem = csrPem;
    }

    public String getSource() {
        return source;
    }

    public void setSource(final Source source) {
        this.source = source.name();
    }

    public Date getActivatedDate() {
        return activatedDate;
    }

    public void setActivatedDate(final Date activatedDate) {
        this.activatedDate = activatedDate;
    }

    public java.time.LocalDate getExpiryWarnedOn() {
        return expiryWarnedOn;
    }

    @Override
    public String toString() {
        return "RealmKey[" + keyId + ", " + realmId + ", " + status + "]"; // never key material
    }
}
