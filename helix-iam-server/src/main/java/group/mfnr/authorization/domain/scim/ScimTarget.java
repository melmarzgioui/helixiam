package group.mfnr.authorization.domain.scim;

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
 * Helix IAM B7: a per-realm outbound SCIM 2.0 provisioning target — a downstream service provider that
 * Helix pushes local user lifecycle changes to (create / update / disable / delete). Authenticated with a
 * bearer {@link #token} stored <b>encrypted at rest</b>. {@link #eventTypes} is a comma-joined allow-list
 * of user event types to sync (blank = all user events).
 */
@Entity
@Table(name = "scim_target")
@EntityListeners(AuditingEntityListener.class)
public class ScimTarget {

    @Id
    @Column(name = "id")
    private String id;

    @Column(name = "realm_id")
    private String realmId;

    @Column(name = "name")
    private String name;

    /** The SCIM service-provider base URL (the {@code /Users} collection hangs off it). */
    @Column(name = "base_url")
    private String baseUrl;

    @Convert(converter = AttributeEncryption.class)
    @Column(name = "token")
    private String token;

    @Column(name = "event_types")
    private String eventTypes = "";

    @Column(name = "enabled")
    private boolean enabled = true;

    @CreationTimestamp
    @Column(name = "creation_date", updatable = false)
    private Date creationDate;

    public ScimTarget() {
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

    public String getBaseUrl() {
        return baseUrl;
    }

    public void setBaseUrl(final String baseUrl) {
        this.baseUrl = baseUrl;
    }

    public String getToken() {
        return token;
    }

    public void setToken(final String token) {
        this.token = token;
    }

    public String getEventTypes() {
        return eventTypes;
    }

    public void setEventTypes(final String eventTypes) {
        this.eventTypes = eventTypes;
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
}
