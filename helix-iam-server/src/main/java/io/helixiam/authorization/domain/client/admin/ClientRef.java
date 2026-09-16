package io.helixiam.authorization.domain.client.admin;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/** Helix IAM E8.5-S3: references a single OAuth client (subscriber-side copy). */
@JsonIgnoreProperties(ignoreUnknown = true)
public record ClientRef(String realmId, String id) {
}
