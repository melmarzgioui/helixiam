package io.helixiam.authorization.amqp.scope;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/** Helix IAM E8.5: publisher-side view of a catalogue claim (mirrors the subscriber copy). */
@JsonIgnoreProperties(ignoreUnknown = true)
public record ClaimDto(String realmId, String claimId, String key, String label, String placeholder, boolean mandatory) {
}
