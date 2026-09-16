package io.helixiam.authorization.amqp.gdpr;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.util.List;

/** Helix IAM GDPR Art. 7: record a consent grant in the ledger (publisher-side copy). */
@JsonIgnoreProperties(ignoreUnknown = true)
public record GdprConsentWriteDto(String realmId, String userId, String clientId, List<String> scopes) {
}
