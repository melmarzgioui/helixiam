/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.domain.federation;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import org.hibernate.annotations.CreationTimestamp;

import java.util.Date;

/**
 * Helix IAM E5: a federated-identity link mapping an external IdP subject to a local user — the
 * persistence behind the broker's account linking. The id is {@code idpAlias|externalSubject}, so an
 * external subject links to exactly one local user per provider.
 */
@Entity
@Table(name = "federated_link")
public class FederatedLinkEntity {

    @Id
    @Column(name = "id")
    private String id;

    @Column(name = "idp_alias")
    private String idpAlias;

    @Column(name = "external_subject")
    private String externalSubject;

    @Column(name = "user_id")
    private String userId;

    @CreationTimestamp
    @Column(name = "creation_date", updatable = false)
    private Date creationDate;

    public FederatedLinkEntity() {
    }

    public FederatedLinkEntity(final String idpAlias, final String externalSubject, final String userId) {
        this.id = key(idpAlias, externalSubject);
        this.idpAlias = idpAlias;
        this.externalSubject = externalSubject;
        this.userId = userId;
    }

    /** The surrogate primary key for an (alias, subject) pair. */
    public static String key(final String idpAlias, final String externalSubject) {
        return idpAlias + "|" + externalSubject;
    }

    public String getId() {
        return id;
    }

    public String getIdpAlias() {
        return idpAlias;
    }

    public String getExternalSubject() {
        return externalSubject;
    }

    public String getUserId() {
        return userId;
    }

    public java.util.Date getCreationDate() {
        return creationDate;
    }
}
