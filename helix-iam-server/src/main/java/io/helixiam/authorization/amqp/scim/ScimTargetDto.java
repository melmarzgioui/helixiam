package io.helixiam.authorization.amqp.scim;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/**
 * Helix IAM B7: publisher-side copy of the subscriber's SCIM target DTO (two-copy, same field order for
 * Jackson-over-AMQP). The {@code token} crosses the internal seam so the provisioning dispatcher can
 * authenticate to the downstream service provider; the admin controller nulls it before returning to the
 * console ({@code tokenSet} stays).
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record ScimTargetDto(String id, String realmId, String name, String baseUrl, String token,
                            boolean tokenSet, String eventTypes, boolean enabled, Long createdAt) {
}
