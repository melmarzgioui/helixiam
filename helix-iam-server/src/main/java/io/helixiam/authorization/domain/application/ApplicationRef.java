package io.helixiam.authorization.domain.application;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/**
 * Helix IAM: a (realm, name) reference for fetch/delete of an Application. Subscriber-side copy of the
 * publisher's two-copy DTO.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record ApplicationRef(String realmId, String name) {
}
