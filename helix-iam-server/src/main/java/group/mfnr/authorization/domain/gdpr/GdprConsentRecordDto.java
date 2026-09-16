package group.mfnr.authorization.domain.gdpr;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.util.List;

/**
 * Helix IAM GDPR Art. 7: one entry in the consent ledger — a per-user, per-client grant or withdrawal of a
 * set of scopes (subscriber-side copy). {@code withdrawnAt == null} means the consent is currently active;
 * a non-null value records when it was withdrawn (the row is kept for audit integrity, never deleted).
 *
 * @param id         ledger row id
 * @param realmId    realm the consent was granted in
 * @param userId     data subject
 * @param clientId   the OAuth client / application the consent is for
 * @param scopes     the scopes granted
 * @param grantedAt  epoch millis the consent was granted
 * @param withdrawnAt epoch millis the consent was withdrawn, or {@code null} while active
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record GdprConsentRecordDto(String id, String realmId, String userId, String clientId, List<String> scopes,
                                   Long grantedAt, Long withdrawnAt) {
}
