package io.helixiam.authorization.amqp.gdpr;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/**
 * Helix IAM GDPR Art. 17: outcome of an erasure (publisher-side copy). {@code found == false} → 404 at the
 * edge; {@code mode} echoes what ran ("hard" | "anonymize").
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record GdprEraseResultDto(boolean found, String mode, String userId) {
}
