package io.helixiam.authorization.amqp.adminrbac;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.util.List;

/**
 * Helix IAM: effective admin permissions for a principal in a realm (publisher copy).
 * {@code modelConfigured=false} = realm has NO grants → enforcement is a no-op (today's behaviour).
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record AdminEffectivePermissionsDto(String realmId, boolean modelConfigured, List<String> permissions) {
}
