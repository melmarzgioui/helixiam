package group.mfnr.authorization.domain.webhook;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/** Helix IAM B6: realm-scoped reference to one webhook subscription (get/delete by id within a realm). */
@JsonIgnoreProperties(ignoreUnknown = true)
public record WebhookRef(String realmId, String id) {
}
