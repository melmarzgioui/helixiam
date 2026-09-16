package io.helixiam.authorization.amqp.client;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/** Helix IAM E8.5-S3: references a single OAuth client (publisher-side copy). */
@JsonIgnoreProperties(ignoreUnknown = true)
public record ClientRef(String realmId, String id) {
}
