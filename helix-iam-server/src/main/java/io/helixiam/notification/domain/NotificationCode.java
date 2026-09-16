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
}
