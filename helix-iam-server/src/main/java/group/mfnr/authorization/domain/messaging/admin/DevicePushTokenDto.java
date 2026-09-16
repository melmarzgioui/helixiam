package group.mfnr.authorization.domain.messaging.admin;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/** Helix IAM notifications (N6c): a registered push device token (subscriber copy). */
@JsonIgnoreProperties(ignoreUnknown = true)
public record DevicePushTokenDto(String realmId, String userId, String platform, String token) {
}
