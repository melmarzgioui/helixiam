package io.helixiam.authorization.domain.provisioning.admin;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/** Helix IAM E11: a SCIM bearer-token verification request (realm + presented token), subscriber copy. */
@JsonIgnoreProperties(ignoreUnknown = true)
public record ScimTokenCheck(String realmId, String token) {
}
