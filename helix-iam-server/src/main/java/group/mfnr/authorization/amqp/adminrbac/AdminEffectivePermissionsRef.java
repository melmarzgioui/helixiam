package group.mfnr.authorization.amqp.adminrbac;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.util.List;

/** Helix IAM: resolve effective admin permissions for a principal holding {@code roleNames} (publisher copy). */
@JsonIgnoreProperties(ignoreUnknown = true)
public record AdminEffectivePermissionsRef(String realmId, List<String> roleNames) {
}
