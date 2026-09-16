package io.helixiam.authorization.domain.gdpr;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/**
 * Helix IAM GDPR Art. 7: withdraw a user's consent for one client (subscriber-side copy). Stamps
 * {@code withdrawn_at} on every still-active ledger row for (realm, user, client); the rows are kept.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record GdprConsentWithdrawDto(String realmId, String userId, String clientId) {
}
