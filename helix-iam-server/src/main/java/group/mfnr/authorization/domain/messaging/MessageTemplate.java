package group.mfnr.authorization.domain.messaging;

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
 * Helix IAM notifications (N1): a per-realm message template, keyed by {@code (realm_id, template_key)}.
 * {@code subject} applies to email templates only; {@code body} carries the message with {@code {{variables}}}
 * (e.g. {@code {{code}}}, {@code {{user}}}, {@code {{realm}}}, {@code {{ttl}}}) substituted at send time.
 */
@Entity
@Table(name = "message_template")
@EntityListeners(AuditingEntityListener.class)
public class MessageTemplate {

    @Id
    @JsonProperty
    @GeneratedValue(strategy = GenerationType.UUID)
    @Column(name = "id", updatable = false)
    private String id;

    @JsonProperty
    @Column(name = "realm_id")
    private String realmId;

    /** Stable key — e.g. {@code otp-sms}, {@code otp-email}, {@code magic-link-email}, {@code push-approval}. */
    @JsonProperty
    @Column(name = "template_key")
    private String templateKey;

    /** {@code SMS} | {@code EMAIL} | {@code PUSH} — which provider channel renders it. */
    @JsonProperty
    @Column(name = "channel")
    private String channel;

    /** Email subject line ({@code null} for SMS/push). */
    @JsonProperty
    @Column(name = "subject")
    private String subject;

    @JsonProperty
    @Column(name = "body", length = 8000)
    private String body;

    @JsonProperty
    @Column(name = "enabled")
    private Boolean enabled = true;

    /** Email templates only: when true the body is delivered as {@code text/html}. SMS/push stay plain text. */
    @JsonProperty
    @Column(name = "html")
    private Boolean html = false;

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
    public String getTemplateKey() { return templateKey; }
    public void setTemplateKey(final String templateKey) { this.templateKey = templateKey; }
    public String getChannel() { return channel; }
    public void setChannel(final String channel) { this.channel = channel; }
    public String getSubject() { return subject; }
    public void setSubject(final String subject) { this.subject = subject; }
    public String getBody() { return body; }
    public void setBody(final String body) { this.body = body; }
    public Boolean getEnabled() { return enabled; }
    public void setEnabled(final Boolean enabled) { this.enabled = enabled; }
    public Boolean getHtml() { return html; }
    public void setHtml(final Boolean html) { this.html = html; }
}
