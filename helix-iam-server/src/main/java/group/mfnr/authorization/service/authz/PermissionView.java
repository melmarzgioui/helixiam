package group.mfnr.authorization.service.authz;

import java.util.List;

/**
 * Helix IAM (Wave 6): the evaluator's view of a permission. {@code type}=RESOURCE|SCOPE; binds a resource
 * and/or scope to a set of policies, combined by {@code decisionStrategy} (UNANIMOUS|AFFIRMATIVE).
 */
public record PermissionView(String name, String type, String resourceName, String scopeName,
                             List<String> policyNames, String decisionStrategy) {
}
