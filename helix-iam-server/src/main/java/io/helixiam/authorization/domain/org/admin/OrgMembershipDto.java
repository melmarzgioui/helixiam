package io.helixiam.authorization.domain.org.admin;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.util.List;

/**
 * Helix IAM Organizations: a user's membership in one organization, shaped for token enrichment — the
 * {@code organizations} claim is an array of these (mirrors the publisher copy).
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record OrgMembershipDto(String id, String name, List<String> roles) {
}
