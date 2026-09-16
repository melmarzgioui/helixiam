package io.helixiam.authorization.amqp.role;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/** Helix IAM E8.5-S2: publisher-side view of a realm role (mirrors the subscriber's domain copy). */
@JsonIgnoreProperties(ignoreUnknown = true)
public record RoleDto(String realmId, String roleId, String name, boolean system, boolean defaultRole) {

    /** Convenience for callers that don't carry the system/default flags (e.g. imports): both default to false. */
    public RoleDto(final String realmId, final String roleId, final String name) {
        this(realmId, roleId, name, false, false);
    }
}
