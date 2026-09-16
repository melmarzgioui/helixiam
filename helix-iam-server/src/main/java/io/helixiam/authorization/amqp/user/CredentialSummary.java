package io.helixiam.authorization.amqp.user;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/** Helix IAM E8.5: one enrolled authentication factor for a realm user (publisher-side copy). */
@JsonIgnoreProperties(ignoreUnknown = true)
public record CredentialSummary(String type, String id, String label, String detail,
                                Long createdAt, Long lastUsedAt, boolean revocable) {
}
