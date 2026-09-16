package io.helixiam.authorization.amqp.org;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/**
 * Helix IAM Organizations: identifies an organization, optionally with a target user and role within the
 * org (mirrors the subscriber copy).
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record OrgRef(String realmId, String orgId, String userId, String role) {
}
