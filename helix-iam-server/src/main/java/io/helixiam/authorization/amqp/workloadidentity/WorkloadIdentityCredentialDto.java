package io.helixiam.authorization.amqp.workloadidentity;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/**
 * Helix IAM WIF: publisher-side copy of the subscriber's federated-credential DTO (two-copy, SAME field
 * order for Jackson-over-AMQP). None of these fields are secret, so all cross the seam and reach the
 * console unmasked. {@code clientId} is the Helix identity a matching workload acts as.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record WorkloadIdentityCredentialDto(String id, String realmId, String name, String issuer,
                                            String jwksUri, String subject, String audience, String clientId,
                                            String scopes, boolean enabled, Long createdAt) {
}
