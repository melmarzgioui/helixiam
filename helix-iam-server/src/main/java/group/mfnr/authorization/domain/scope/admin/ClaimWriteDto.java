package group.mfnr.authorization.domain.scope.admin;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/**
 * Helix IAM E8.5: create/update payload for a catalogue claim. {@code claimId} is null on create and set
 * on update (the {@code key} is immutable, so it's ignored on update). Mirrors the publisher copy.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record ClaimWriteDto(String realmId, String claimId, String key, String label, String placeholder,
                            boolean mandatory) {
}
