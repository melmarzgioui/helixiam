package group.mfnr.authorization.domain.client.role;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/** Helix IAM (Wave 4): references a client (and optionally one of its roles by {@code name}). Subscriber copy. */
@JsonIgnoreProperties(ignoreUnknown = true)
public record ClientRoleRef(String realmId, String clientId, String name) {
}
