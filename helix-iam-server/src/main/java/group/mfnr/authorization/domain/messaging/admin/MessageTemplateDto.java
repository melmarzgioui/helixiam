package group.mfnr.authorization.domain.messaging.admin;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/** Helix IAM notifications (N1): a per-realm message template (read + write share this shape). */
@JsonIgnoreProperties(ignoreUnknown = true)
public record MessageTemplateDto(String id, String realmId, String templateKey, String channel,
                                 String subject, String body, boolean enabled, boolean html) {
}
