package io.helixiam.authorization.idp.provisioning;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/** Helix IAM E11: bind a freshly-created OAuth client to a new registration_access_token (publisher copy). */
@JsonIgnoreProperties(ignoreUnknown = true)
public record DcrBindRequest(String realmId, String clientInternalId, String clientId) {
}
