package group.mfnr.authorization.amqp.authz;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.util.List;

@JsonIgnoreProperties(ignoreUnknown = true)
public record AuthzEvalResult(boolean granted, List<String> grantingPermissions, List<String> denyingPermissions) {
}
