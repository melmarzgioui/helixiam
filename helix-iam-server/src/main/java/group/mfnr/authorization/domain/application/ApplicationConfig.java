package group.mfnr.authorization.domain.application;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/**
 * Helix IAM: a per-realm Application as it crosses AMQP and the admin API. Subscriber-side copy of the
 * publisher's two-copy DTO.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record ApplicationConfig(String realmId, String name, String description, String subjectClaim,
                                String authFlowAlias, boolean enabled, String displayName) {
}
