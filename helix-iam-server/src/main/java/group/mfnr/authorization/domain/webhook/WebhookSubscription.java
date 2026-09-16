package group.mfnr.authorization.domain.webhook;

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
 * Helix IAM B6: a per-realm outbound webhook subscription. Each matching audit event is POSTed to
 * {@link #url} with an HMAC-SHA256 signature derived from {@link #secret} (stored <b>encrypted at
 * rest</b>). {@link #eventTypes} is a comma-joined allow-list of event types (blank = all events).
 */
@Entity
@Table(name = "webhook_subscription")
@EntityListeners(AuditingEntityListener.class)
public class WebhookSubscription {

    @Id
    @Column(name = "id")
    private String id;

    @Column(name = "realm_id")
    private String realmId;

    @Column(name = "name")
    private String name;

    @Column(name = "url")
    private String url;

    @Convert(converter = AttributeEncryption.class)
    @Column(name = "secret")
    private String secret;

    @Column(name = "event_types")
    private String eventTypes = "";

    @Column(name = "enabled")
    private boolean enabled = true;

    @CreationTimestamp
    @Column(name = "creation_date", updatable = false)
    private Date creationDate;

    public WebhookSubscription() {
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

    public String getUrl() {
        return url;
    }

    public void setUrl(final String url) {
        this.url = url;
    }

    public String getSecret() {
        return secret;
    }

    public void setSecret(final String secret) {
        this.secret = secret;
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
