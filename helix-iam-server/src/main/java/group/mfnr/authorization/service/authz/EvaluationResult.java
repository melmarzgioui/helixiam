package group.mfnr.authorization.service.authz;

import java.util.List;

/** Helix IAM (Wave 6): the outcome of evaluating an authorization request. */
public record EvaluationResult(boolean granted, List<String> grantingPermissions, List<String> denyingPermissions) {
}
