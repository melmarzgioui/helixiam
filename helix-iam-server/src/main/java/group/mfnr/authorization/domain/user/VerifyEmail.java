package group.mfnr.authorization.domain.user;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

@Entity
@Table(name = "user_credentials")
@JsonIgnoreProperties(ignoreUnknown = true)
public class VerifyEmail {

    @Id
    @Column(name = "user_id", updatable = false)
    private String userId;

    @JsonProperty
    @Column(name = "email_verified")
    private boolean emailVerified = true;

    @JsonProperty
    @Column(name = "account_locked")
    private boolean accountLocked = false;

    public void setUserId(final String userId) {
        this.userId = userId;
    }
}
