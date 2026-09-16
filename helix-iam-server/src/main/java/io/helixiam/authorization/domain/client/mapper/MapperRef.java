package io.helixiam.authorization.domain.client.mapper;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/**
 * Helix IAM (Wave 3): references one protocol mapper of a client (subscriber copy). {@code mapperId} is null
 * when the request addresses the client as a whole (e.g. list).
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record MapperRef(String realmId, String clientId, String mapperId) {
}
