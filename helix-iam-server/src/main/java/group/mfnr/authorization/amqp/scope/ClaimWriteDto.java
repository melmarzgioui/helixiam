package group.mfnr.authorization.amqp.scope;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/** Helix IAM E8.5: create/update payload for a catalogue claim (mirrors the subscriber copy). */
@JsonIgnoreProperties(ignoreUnknown = true)
public record ClaimWriteDto(String realmId, String claimId, String key, String label, String placeholder,
                            boolean mandatory) {
}
