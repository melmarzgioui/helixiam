package group.mfnr.authorization.amqp.gdpr;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.util.List;

/**
 * Helix IAM GDPR Art. 7: one entry in the consent ledger — a per-user, per-client grant or withdrawal of a
 * set of scopes (publisher-side copy). {@code withdrawnAt == null} means the consent is currently active.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record GdprConsentRecordDto(String id, String realmId, String userId, String clientId, List<String> scopes,
                                   Long grantedAt, Long withdrawnAt) {
}
