package io.helixiam.notification.domain;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.HashMap;
import java.util.Map;

@JsonIgnoreProperties(ignoreUnknown = true)
public class NotificationRequest {

    @JsonProperty
    private final String type;
    @JsonProperty
    private String deviceId;

    @JsonProperty
    private String emailAddress;
    @JsonProperty
    private String mobile;

    @JsonProperty
    private NotificationCode notificationCode;

    @JsonProperty
    private final Map<String, String> additionalData = new HashMap<>();

    public NotificationRequest(final String type) {
        this.type = type;
    }

    public String getType() {
        return type;
    }

    public String getDeviceId() {
        return deviceId;
    }

    public String getEmailAddress() {
        return emailAddress;
    }

    public String getMobile() {
        return mobile;
    }

    public NotificationCode getNotificationCode() {
        return notificationCode;
    }

    public Map<String, String> getAdditionalData() {
        return additionalData;
    }

    public void setDeviceId(final String deviceId) {
        this.deviceId = deviceId;
    }

    public void setEmailAddress(final String emailAddress) {
        this.emailAddress = emailAddress;
    }

    public void setMobile(final String mobile) {
        this.mobile = mobile;
    }

    public void setNotificationCode(final NotificationCode notificationCode) {
        this.notificationCode = notificationCode;
    }
}
