package io.helixiam.authorization.domain.gdpr;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.util.List;

/**
 * Helix IAM GDPR Art. 7: payload to record a consent grant in the ledger (subscriber-side copy). Used when
 * a user authorizes an application; the ledger then exposes a withdraw operation keyed by (realm, user,
 * client).
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record GdprConsentWriteDto(String realmId, String userId, String clientId, List<String> scopes) {
}
