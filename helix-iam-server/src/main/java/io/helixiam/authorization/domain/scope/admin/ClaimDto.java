package io.helixiam.authorization.domain.scope.admin;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/** Helix IAM E8.5: a claim type from the realm's catalogue. Mirrors the publisher copy. */
@JsonIgnoreProperties(ignoreUnknown = true)
public record ClaimDto(String realmId, String claimId, String key, String label, String placeholder, boolean mandatory) {
}
