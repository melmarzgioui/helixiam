package io.helixiam.authorization.domain;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

@JsonIgnoreProperties(ignoreUnknown = true)
public class ChangePassword {

    @JsonProperty
    private final String code;

    @JsonProperty
    private String oldPassword;

    @JsonProperty
    private String newPassword;

    @JsonProperty
    private String repeatPassword;

    public ChangePassword(final String code) {
        this.code = code;
        this.oldPassword = "FORGOT";
    }

    public String getNewPassword() {
        return newPassword;
    }

    public void setNewPassword(final String newPassword) {
        this.newPassword = newPassword;
    }

    public String getCode() {
        return code;
    }

    public String getRepeatPassword() {
        return repeatPassword;
    }

    public void setRepeatPassword(final String repeatPassword) {
        this.repeatPassword = repeatPassword;
    }
}
