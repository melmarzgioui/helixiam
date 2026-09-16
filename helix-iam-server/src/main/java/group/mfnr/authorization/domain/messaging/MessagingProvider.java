package group.mfnr.authorization.domain.messaging;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.helixiam.persistence.security.AttributeEncryption;
import jakarta.persistence.Column;
import jakarta.persistence.Convert;
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
 * Helix IAM notifications (N1): one configured delivery provider for a realm — keyed by
 * {@code (realm_id, channel, driver)}. The non-secret settings live in {@link #config} (a JSON blob whose
 * shape depends on the driver); the single sensitive blob (auth token / SMTP password / API key / FCM
 * service-account JSON / APNs {@code .p8} key) lives in {@link #secret}, encrypted at rest like a client
 * secret. {@code SMS}/{@code EMAIL} realms normally enable one driver; {@code PUSH} enables both FCM+APNs.
 */
@Entity
@Table(name = "messaging_provider")
@EntityListeners(AuditingEntityListener.class)
public class MessagingProvider {

    @Id
    @JsonProperty
    @GeneratedValue(strategy = GenerationType.UUID)
    @Column(name = "id", updatable = false)
    private String id;

    @JsonProperty
    @Column(name = "realm_id")
    private String realmId;

    /** {@code SMS} | {@code EMAIL} | {@code PUSH}. */
    @JsonProperty
    @Column(name = "channel")
    private String channel;

    /** SMS: {@code TWILIO}/{@code HTTP}; EMAIL: {@code SMTP}/{@code HTTP}; PUSH: {@code FCM}/{@code APNS}. */
    @JsonProperty
    @Column(name = "driver")
    private String driver;

    @JsonProperty
    @Column(name = "enabled")
    private Boolean enabled = false;

    /** From-number (SMS) / from-email (EMAIL); unused for PUSH. */
    @JsonProperty
    @Column(name = "from_address")
    private String fromAddress;

    @JsonProperty
    @Column(name = "from_name")
    private String fromName;

    /** Non-secret driver settings as JSON (host/port, url+headers, project id, apns key/team/topic, …). */
    @JsonProperty
    @Column(name = "config", length = 8000)
    private String config;

    /** The single sensitive credential blob — encrypted at rest. */
    @JsonProperty
    @Convert(converter = AttributeEncryption.class)
    @Column(name = "secret", length = 8000)
    private String secret;

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
    public String getChannel() { return channel; }
    public void setChannel(final String channel) { this.channel = channel; }
    public String getDriver() { return driver; }
    public void setDriver(final String driver) { this.driver = driver; }
    public Boolean getEnabled() { return enabled; }
    public void setEnabled(final Boolean enabled) { this.enabled = enabled; }
    public String getFromAddress() { return fromAddress; }
    public void setFromAddress(final String fromAddress) { this.fromAddress = fromAddress; }
    public String getFromName() { return fromName; }
    public void setFromName(final String fromName) { this.fromName = fromName; }
    public String getConfig() { return config; }
    public void setConfig(final String config) { this.config = config; }
    public String getSecret() { return secret; }
    public void setSecret(final String secret) { this.secret = secret; }
}
