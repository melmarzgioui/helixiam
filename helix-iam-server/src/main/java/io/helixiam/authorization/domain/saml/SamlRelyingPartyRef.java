package io.helixiam.authorization.domain.saml;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/**
 * Helix IAM: a (realm, entityId) reference for fetch/delete of a SAML relying party. Subscriber-side
 * copy of the publisher's two-copy DTO.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record SamlRelyingPartyRef(String realmId, String entityId) {
}
