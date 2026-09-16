package group.mfnr.authorization.amqp.application;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/**
 * Helix IAM: a per-realm Application as it crosses AMQP and the admin API. Publisher-side copy of the
 * two-copy DTO.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record ApplicationConfig(String realmId, String name, String description, String subjectClaim,
                                String authFlowAlias, boolean enabled, String displayName) {
}
