/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.service.authz;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Helix IAM (Wave 6): the fine-grained authorization decision engine. */
class AuthorizationEvaluatorTest {

    private static Map<String, PolicyView> policies(final PolicyView... ps) {
        return java.util.Arrays.stream(ps).collect(java.util.stream.Collectors.toMap(PolicyView::name, p -> p));
    }

    @Test
    void grantsWhenRoleMatchesAResourcePermission() {
        final var perms = List.of(new PermissionView("p", "RESOURCE", "report", null, List.of("admins"), "UNANIMOUS"));
        final var pol = policies(new PolicyView("admins", "ROLE", "POSITIVE", Set.of("admin")));
        final EvaluationResult r = AuthorizationEvaluator.evaluate("report", null, Set.of("admin"), perms, pol, "UNANIMOUS");
        assertTrue(r.granted());
        assertEquals(List.of("p"), r.grantingPermissions());
    }

    @Test
    void deniesWhenRequesterLacksTheRole() {
        final var perms = List.of(new PermissionView("p", "RESOURCE", "report", null, List.of("admins"), "UNANIMOUS"));
        final var pol = policies(new PolicyView("admins", "ROLE", "POSITIVE", Set.of("admin")));
        final EvaluationResult r = AuthorizationEvaluator.evaluate("report", null, Set.of("viewer"), perms, pol, "UNANIMOUS");
        assertFalse(r.granted());
    }

    @Test
    void negativeLogicInvertsTheRoleMatch() {
        // a NEGATIVE role policy permits everyone WITHOUT the role (e.g. "deny banned users")
        final var perms = List.of(new PermissionView("p", "RESOURCE", "report", null, List.of("not-banned"), "UNANIMOUS"));
        final var pol = policies(new PolicyView("not-banned", "ROLE", "NEGATIVE", Set.of("banned")));
        assertTrue(AuthorizationEvaluator.evaluate("report", null, Set.of("viewer"), perms, pol, "UNANIMOUS").granted());
        assertFalse(AuthorizationEvaluator.evaluate("report", null, Set.of("banned"), perms, pol, "UNANIMOUS").granted());
    }

    @Test
    void unanimousRequiresAllPoliciesToPermit() {
        final var perms = List.of(new PermissionView("p", "RESOURCE", "report", null, List.of("admins", "auditors"), "UNANIMOUS"));
        final var pol = policies(new PolicyView("admins", "ROLE", "POSITIVE", Set.of("admin")),
                new PolicyView("auditors", "ROLE", "POSITIVE", Set.of("auditor")));
        assertTrue(AuthorizationEvaluator.evaluate("report", null, Set.of("admin", "auditor"), perms, pol, "UNANIMOUS").granted());
        assertFalse(AuthorizationEvaluator.evaluate("report", null, Set.of("admin"), perms, pol, "UNANIMOUS").granted());
    }

    @Test
    void affirmativePermissionPermitsIfAnyPolicyPermits() {
        final var perms = List.of(new PermissionView("p", "RESOURCE", "report", null, List.of("admins", "auditors"), "AFFIRMATIVE"));
        final var pol = policies(new PolicyView("admins", "ROLE", "POSITIVE", Set.of("admin")),
                new PolicyView("auditors", "ROLE", "POSITIVE", Set.of("auditor")));
        assertTrue(AuthorizationEvaluator.evaluate("report", null, Set.of("admin"), perms, pol, "UNANIMOUS").granted());
    }

    @Test
    void scopePermissionMatchesOnScope() {
        final var perms = List.of(new PermissionView("p", "SCOPE", null, "delete", List.of("admins"), "UNANIMOUS"));
        final var pol = policies(new PolicyView("admins", "ROLE", "POSITIVE", Set.of("admin")));
        assertTrue(AuthorizationEvaluator.evaluate("report", "delete", Set.of("admin"), perms, pol, "UNANIMOUS").granted());
        // a different scope is not covered → default deny
        assertFalse(AuthorizationEvaluator.evaluate("report", "read", Set.of("admin"), perms, pol, "UNANIMOUS").granted());
    }

    @Test
    void defaultDenyWhenNoPermissionApplies() {
        final EvaluationResult r = AuthorizationEvaluator.evaluate("report", null, Set.of("admin"), List.of(), Map.of(), "UNANIMOUS");
        assertFalse(r.granted());
    }

    @Test
    void serverAffirmativeGrantsIfAnyApplicablePermissionGrants() {
        final var perms = List.of(
                new PermissionView("p1", "RESOURCE", "report", null, List.of("admins"), "UNANIMOUS"),
                new PermissionView("p2", "RESOURCE", "report", null, List.of("auditors"), "UNANIMOUS"));
        final var pol = policies(new PolicyView("admins", "ROLE", "POSITIVE", Set.of("admin")),
                new PolicyView("auditors", "ROLE", "POSITIVE", Set.of("auditor")));
        // requester is only an auditor: AFFIRMATIVE server strategy still grants via p2
        assertTrue(AuthorizationEvaluator.evaluate("report", null, Set.of("auditor"), perms, pol, "AFFIRMATIVE").granted());
        // UNANIMOUS server strategy would require BOTH permissions to grant → denied
        assertFalse(AuthorizationEvaluator.evaluate("report", null, Set.of("auditor"), perms, pol, "UNANIMOUS").granted());
    }
}
