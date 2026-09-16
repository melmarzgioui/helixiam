package io.helixiam.authorization.amqp.authzstore;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.util.List;

/**
 * Helix IAM (Q1): the wire form of one stored {@code OAuth2Authorization} when the token store is routed
 * through the queue. The {@code blob} is the base64 of the serialized authorization (the publisher owns
 * (de)serialization — the subscriber treats it as opaque). {@code tokenKeys} are the code/token/state values
 * indexed for {@code findByToken}; {@code expiresAtEpochMilli} lets the store expire spent rows.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record AuthorizationRecord(String id, String principalName, String grantType, String blob,
                                  List<String> tokenKeys, Long expiresAtEpochMilli) {
}
