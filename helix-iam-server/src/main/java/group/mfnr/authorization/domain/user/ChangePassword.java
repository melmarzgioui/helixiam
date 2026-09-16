package group.mfnr.authorization.domain.user;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.persistence.*;

@Entity
@Table(name = "user_credentials")
@JsonIgnoreProperties(ignoreUnknown = true)
public class ChangePassword {

    @Id
    @Column(name = "user_id", updatable = false)
    private String userId;

    @JsonProperty
    @Transient
    private String code;

    @JsonProperty
    @Transient
    private String oldPassword;

    @JsonProperty
    @Column(name = "password")
    private String newPassword;


    @JsonProperty
    @Column(name = "password_salt_value")
    private String passwordSaltValue;

    @JsonProperty
    @Transient
    private String repeatPassword;

    public String getNewPassword() {
        return newPassword;
    }

    public void setUserId(final String userId) {
        this.userId = userId;
    }

    public void setNewPassword(final String newPassword) {
        this.newPassword = newPassword;
        this.repeatPassword = newPassword;
    }

    public void setPasswordSaltValue(final String passwordSaltValue) {
        this.passwordSaltValue = passwordSaltValue;
    }

    public String getCode() {
        return code;
    }
}
