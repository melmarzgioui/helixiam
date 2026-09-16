package io.helixiam.authorization.domain.application;

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
 * Helix IAM: an Application (Service Provider) — the protocol-agnostic top-level object (WSO2/Okta
 * model), partitioned per realm. An OIDC client and/or a SAML relying party link UP to it; the shared
 * policy that applies to whichever protocol the app uses — the subject claim and the login flow — lives
 * here. The id is {@code realmId|name}, so a name is unique within a realm.
 */
@Entity
@Table(name = "application")
@EntityListeners(AuditingEntityListener.class)
public class ApplicationEntity {

    @Id
    @Column(name = "id")
    private String id;

    @Column(name = "realm_id")
    private String realmId;

    @Column(name = "name")
    private String name;

    @Column(name = "display_name")
    private String displayName;

    @Column(name = "description")
    private String description;

    @Column(name = "subject_claim")
    private String subjectClaim;

    @Column(name = "auth_flow_alias")
    private String authFlowAlias;

    @Column(name = "enabled")
    private boolean enabled = true;

    @CreationTimestamp
    @Column(name = "creation_date", updatable = false)
    private Date creationDate;

    @LastModifiedDate
    @Column(name = "modify_date")
    private Date modifyDate;

    /** The surrogate primary key for a (realm, name) pair. */
    public static String key(final String realmId, final String name) {
        return realmId + "|" + name;
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

    public String getName() {
        return name;
    }

    public void setName(final String name) {
        this.name = name;
    }

    public String getDisplayName() {
        return displayName;
    }

    public void setDisplayName(final String displayName) {
        this.displayName = displayName;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(final String description) {
        this.description = description;
    }

    public String getSubjectClaim() {
        return subjectClaim;
    }

    public void setSubjectClaim(final String subjectClaim) {
        this.subjectClaim = subjectClaim;
    }

    public String getAuthFlowAlias() {
        return authFlowAlias;
    }

    public void setAuthFlowAlias(final String authFlowAlias) {
        this.authFlowAlias = authFlowAlias;
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
