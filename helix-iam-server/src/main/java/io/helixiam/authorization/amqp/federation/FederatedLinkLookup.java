package io.helixiam.authorization.amqp.federation;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/**
 * Helix IAM E5.3: AMQP request DTO — resolve the local user previously linked to an external
 * identity. JSON-marshalled, two-copy on each side (mirrored in the subscriber).
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record FederatedLinkLookup(String idpAlias, String externalSubject) {
}
