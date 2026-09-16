package group.mfnr.authorization.domain.gdpr;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/**
 * Helix IAM GDPR Art. 17: outcome of an erasure (subscriber-side copy). {@code found == false} when the
 * subject did not exist (a 404 on the edge). {@code mode} echoes what actually ran ("hard" | "anonymize").
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record GdprEraseResultDto(boolean found, String mode, String userId) {
}
