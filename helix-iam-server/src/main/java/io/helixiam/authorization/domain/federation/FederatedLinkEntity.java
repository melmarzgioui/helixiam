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

    /** Round 6: the realm the link belongs to; a link signs its user in only there. */
    @Column(name = "realm_id")
    private String realmId;

    @Column(name = "idp_alias")
    private String idpAlias;

    @Column(name = "external_subject")
    private String externalSubject;

    @Column(name = "user_id")
    private String userId;

    @CreationTimestamp
    @Column(name = "creation_date", updatable = false)
    private Date creationDate;

    /** Round 6: how the link was made ({@link LinkProvenance}); null on rows of unknown origin. */
    @Column(name = "created_via")
    private String createdVia;

    public String getCreatedVia() {
        return createdVia;
    }

    public void setCreatedVia(final String createdVia) {
        this.createdVia = createdVia;
    }

    public FederatedLinkEntity() {
    }

    /** A link of unknown realm (tests and pre-rc.12 shapes only); production code names the realm. */
    public FederatedLinkEntity(final String idpAlias, final String externalSubject, final String userId) {
        this(null, idpAlias, externalSubject, userId);
    }

    public FederatedLinkEntity(final String realmId, final String idpAlias, final String externalSubject,
                               final String userId) {
        this.id = key(realmId, idpAlias, externalSubject);
        this.realmId = realmId;
        this.idpAlias = idpAlias;
        this.externalSubject = externalSubject;
        this.userId = userId;
    }

    /** The surrogate primary key of a (realm, alias, subject) link. */
    public static String key(final String realmId, final String idpAlias, final String externalSubject) {
        return realmId == null ? idpAlias + "|" + externalSubject : realmId + "|" + idpAlias + "|" + externalSubject;
    }

    public String getRealmId() {
        return realmId;
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
