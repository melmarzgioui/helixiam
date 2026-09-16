package group.mfnr.authorization.amqp.adminrbac;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/** Helix IAM: one entry in the admin-permission catalogue (publisher copy of the two-copy DTO). */
@JsonIgnoreProperties(ignoreUnknown = true)
public record AdminPermissionDto(String key, String label) {
}
