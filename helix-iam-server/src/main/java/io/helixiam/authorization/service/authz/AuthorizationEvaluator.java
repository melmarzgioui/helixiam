/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.service.authz;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Helix IAM (Wave 6): the fine-grained authorization decision engine (Keycloak Authorization-Services style).
 * Pure — no I/O — so it can be unit-tested and run inline on an admin "Evaluate" request or a future UMA grant.
 *
 * <p>For a requested {@code resource}/{@code scope} and the requester's roles, it finds the applicable
 * permissions, evaluates each permission's role policies (honouring {@code POSITIVE}/{@code NEGATIVE} logic),
 * combines policy results by the permission's decision strategy, then combines permission results by the
 * resource server's decision strategy. Default is deny: no applicable permission → not granted.
 */
public final class AuthorizationEvaluator {

    private static final String AFFIRMATIVE = "AFFIRMATIVE";

    private AuthorizationEvaluator() {
    }

    public static EvaluationResult evaluate(final String resource, final String scope, final Set<String> requesterRoles,
                                            final List<PermissionView> permissions, final Map<String, PolicyView> policiesByName,
                                            final String serverDecisionStrategy) {
        final List<String> granting = new ArrayList<>();
        final List<String> denying = new ArrayList<>();
        final Set<String> roles = requesterRoles == null ? Set.of() : requesterRoles;

        for (final PermissionView p : permissions == null ? List.<PermissionView>of() : permissions) {
            if (!applies(p, resource, scope)) {
                continue;
            }
            if (permissionGrants(p, roles, policiesByName)) {
                granting.add(p.name());
            } else {
                denying.add(p.name());
            }
        }

        final boolean anyApplicable = !granting.isEmpty() || !denying.isEmpty();
        final boolean granted;
        if (!anyApplicable) {
            granted = false; // default deny
        } else if (AFFIRMATIVE.equals(serverDecisionStrategy)) {
            granted = !granting.isEmpty();
        } else { // UNANIMOUS
            granted = denying.isEmpty();
        }
        return new EvaluationResult(granted, List.copyOf(granting), List.copyOf(denying));
    }

    private static boolean applies(final PermissionView p, final String resource, final String scope) {
        if ("SCOPE".equals(p.type())) {
            if (p.scopeName() == null || !p.scopeName().equals(scope)) {
                return false;
            }
            return p.resourceName() == null || p.resourceName().equals(resource);
        }
        // RESOURCE permission
        return p.resourceName() != null && p.resourceName().equals(resource);
    }

    private static boolean permissionGrants(final PermissionView p, final Set<String> roles, final Map<String, PolicyView> policiesByName) {
        final List<PolicyView> applied = new ArrayList<>();
        for (final String name : p.policyNames() == null ? List.<String>of() : p.policyNames()) {
            final PolicyView pol = policiesByName == null ? null : policiesByName.get(name);
            if (pol != null) {
                applied.add(pol);
            }
        }
        if (applied.isEmpty()) {
            return false; // a permission with no resolvable policies grants nothing
        }
        if (AFFIRMATIVE.equals(p.decisionStrategy())) {
            return applied.stream().anyMatch(pol -> policyPermits(pol, roles));
        }
        return applied.stream().allMatch(pol -> policyPermits(pol, roles)); // UNANIMOUS
    }

    private static boolean policyPermits(final PolicyView pol, final Set<String> roles) {
        final boolean match = pol.roles() != null && pol.roles().stream().anyMatch(roles::contains);
        return "NEGATIVE".equals(pol.logic()) != match; // POSITIVE: match; NEGATIVE: !match
    }
}
