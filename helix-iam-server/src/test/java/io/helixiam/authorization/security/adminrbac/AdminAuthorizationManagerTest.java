/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.security.adminrbac;

import io.helixiam.authorization.amqp.adminrbac.AdminEffectivePermissionsDto;
import io.helixiam.authorization.amqp.adminrbac.AdminEffectivePermissionsRef;
import io.helixiam.authorization.amqp.adminrbac.AdminRbacPublisher;
import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;

import java.util.List;
import java.util.function.Supplier;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/** Helix IAM: admin-RBAC enforcement — dev-open no-op, default-safe allow, granted vs denied, fail-open. */
class AdminAuthorizationManagerTest {

    private AdminRbacPublisher publisher;

    @BeforeEach
    void setUp() {
        publisher = mock(AdminRbacPublisher.class);
    }

    private static RequestAuthorizationContext ctx(final String method, final String uri) {
        final HttpServletRequest req = mock(HttpServletRequest.class);
        when(req.getRequestURI()).thenReturn(uri);
        when(req.getContextPath()).thenReturn("");
        when(req.getMethod()).thenReturn(method);
        return new RequestAuthorizationContext(req);
    }

    private static Supplier<Authentication> principal(final String... roles) {
        final Authentication auth = new UsernamePasswordAuthenticationToken(
                "u-1", "x", AuthorityUtils.createAuthorityList(roles));
        return () -> auth;
    }

    @Test
    void resolvesThePermissionOnTheDecodedPath_asSpringMvcRoutesIt() {
        // Security review: /keys percent-encoded as k%65ys used to resolve to the manage-realm default.
        when(publisher.effective(any())).thenReturn(
                new AdminEffectivePermissionsDto("gov", true, List.of("manage-realm", "manage-users")));
        final AdminAuthorizationManager mgr = new AdminAuthorizationManager(publisher, false);
        assertThat(mgr.authorize(principal("r"), ctx("POST", "/admin/realms/gov/k%65ys/import")).isGranted()).isFalse();
        assertThat(mgr.authorize(principal("r"), ctx("POST", "/admin/realms/gov/%6Beys/rotate")).isGranted()).isFalse();
        assertThat(mgr.authorize(principal("r"), ctx("POST", "/admin/realms/gov/keys;x=1/import")).isGranted()).isFalse();
        assertThat(mgr.authorize(principal("r"), ctx("POST", "/admin/realms/gov/cl%69ents")).isGranted()).isFalse();
        assertThat(mgr.authorize(principal("r"), ctx("POST", "/admin/realms/gov/u%73ers")).isGranted()).isTrue();
        assertThat(mgr.authorize(principal("r"), ctx("GET", "/admin/realms/gov/keys")).isGranted()).isTrue();
    }

    @Test
    void permits_isTheSameDecisionForControllers() {
        when(publisher.effective(any())).thenReturn(
                new AdminEffectivePermissionsDto("gov", true, List.of("manage-realm")));
        final AdminAuthorizationManager mgr = new AdminAuthorizationManager(publisher, false);
        assertThat(mgr.permits(principal("r").get(), "gov", "realm-admin")).isFalse();
        assertThat(mgr.permits(principal("r").get(), "gov", "manage-realm")).isTrue();
        assertThat(mgr.permits(principal("admin_master").get(), "gov", "realm-admin")).isTrue();
        assertThat(mgr.permits(null, "gov", "manage-realm")).isFalse();
        assertThat(new AdminAuthorizationManager(publisher, true).permits(null, "gov", "realm-admin")).isTrue();
    }

    @Test
    void devOpen_alwaysGrants_neverCallsPublisher() {
        final AdminAuthorizationManager mgr = new AdminAuthorizationManager(publisher, true);
        assertThat(mgr.authorize(principal("anything"), ctx("DELETE", "/admin/realms/gov/users/u-9")).isGranted()).isTrue();
        verify(publisher, times(0)).effective(any());
    }

    @Test
    void unconfiguredRealm_allowsRealmAdmin_butDeniesOrdinaryUser() {
        // Security review: an unconfigured realm (the DEFAULT state) previously granted to ANY
        // authenticated principal — privilege escalation. It now requires realm-admin for that realm.
        when(publisher.effective(any())).thenReturn(new AdminEffectivePermissionsDto("gov", false, List.of()));
        final AdminAuthorizationManager mgr = new AdminAuthorizationManager(publisher, false);
        assertThat(mgr.authorize(principal("auditor"), ctx("POST", "/admin/realms/gov/users")).isGranted()).isFalse();
        assertThat(mgr.authorize(principal("admin_gov"), ctx("POST", "/admin/realms/gov/users")).isGranted()).isTrue();
    }

    @Test
    void grantsWhenPrincipalHasRequiredPermission() {
        when(publisher.effective(any())).thenReturn(
                new AdminEffectivePermissionsDto("gov", true, List.of("manage-users")));
        final AdminAuthorizationManager mgr = new AdminAuthorizationManager(publisher, false);
        assertThat(mgr.authorize(principal("user-admin"), ctx("POST", "/admin/realms/gov/users")).isGranted()).isTrue();
    }

    @Test
    void deniesWhenPrincipalLacksRequiredPermission() {
        when(publisher.effective(any())).thenReturn(
                new AdminEffectivePermissionsDto("gov", true, List.of("view-users")));
        final AdminAuthorizationManager mgr = new AdminAuthorizationManager(publisher, false);
        // POST (write) needs manage-users; principal only has view-users.
        assertThat(mgr.authorize(principal("auditor"), ctx("POST", "/admin/realms/gov/users")).isGranted()).isFalse();
    }

    @Test
    void viewerCanReadButNotWrite() {
        when(publisher.effective(any())).thenReturn(
                new AdminEffectivePermissionsDto("gov", true, List.of("view-users")));
        final AdminAuthorizationManager mgr = new AdminAuthorizationManager(publisher, false);
        assertThat(mgr.authorize(principal("auditor"), ctx("GET", "/admin/realms/gov/users")).isGranted()).isTrue();
        assertThat(mgr.authorize(principal("auditor"), ctx("DELETE", "/admin/realms/gov/users/u-9")).isGranted()).isFalse();
    }

    @Test
    void realmAdminGrantsEverything() {
        when(publisher.effective(any())).thenReturn(
                new AdminEffectivePermissionsDto("gov", true, List.of("realm-admin")));
        final AdminAuthorizationManager mgr = new AdminAuthorizationManager(publisher, false);
        assertThat(mgr.authorize(principal("superadmin"), ctx("DELETE", "/admin/realms/gov/clients/c-1")).isGranted()).isTrue();
    }

    @Test
    void resolutionFailure_stillAllowsRealmAdmin_butDeniesOrdinaryUser() {
        // Security review: an RBAC resolution failure previously granted to ANY authenticated principal.
        // It now degrades to "must be realm-admin" — admins are never locked out by an RBAC outage,
        // but an ordinary user cannot ride the failure into the admin API.
        when(publisher.effective(any())).thenThrow(new RuntimeException("RBAC backend down"));
        final AdminAuthorizationManager mgr = new AdminAuthorizationManager(publisher, false);
        assertThat(mgr.authorize(principal("user-admin"), ctx("POST", "/admin/realms/gov/users")).isGranted()).isFalse();
        assertThat(mgr.authorize(principal("admin_gov"), ctx("POST", "/admin/realms/gov/users")).isGranted()).isTrue();
    }

    @Test
    void anonymousPrincipal_onAdminPath_isDenied() {
        // C1 regression guard: this manager is the SOLE rule for /admin/**, so an anonymous caller
        // must be DENIED here — never granted on the assumption another rule gates login first.
        final AdminAuthorizationManager mgr = new AdminAuthorizationManager(publisher, false);
        final Authentication anon = new AnonymousAuthenticationToken(
                "key", "anonymousUser", AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS"));
        assertThat(mgr.authorize(() -> anon, ctx("POST", "/admin/realms/gov/users")).isGranted()).isFalse();
    }

    @Test
    void unauthenticatedPrincipal_onAdminPath_isDenied() {
        final AdminAuthorizationManager mgr = new AdminAuthorizationManager(publisher, false);
        assertThat(mgr.authorize(() -> null, ctx("GET", "/admin/realms/gov/users")).isGranted()).isFalse();
    }

    @Test
    void legacyRoleAdminAuthority_isNotAcceptedAsRealmAdmin() {
        // Admin means exactly one authority: admin_<realmId>. The legacy ROLE_ADMIN_<realmId> is NOT
        // accepted — nothing reachable grants it (its only producer, TenantService.createTenant, has no
        // callers), so honouring it would widen a security-critical check for no live caller.
        when(publisher.effective(any())).thenReturn(new AdminEffectivePermissionsDto("gov", false, List.of()));
        final AdminAuthorizationManager mgr = new AdminAuthorizationManager(publisher, false);
        assertThat(mgr.authorize(principal("ROLE_ADMIN_gov"), ctx("POST", "/admin/realms/gov/users")).isGranted()).isFalse();
        assertThat(mgr.authorize(principal("admin_gov"), ctx("POST", "/admin/realms/gov/users")).isGranted()).isTrue();
    }

    @Test
    void nonAdminPath_isNotEnforced() {
        final AdminAuthorizationManager mgr = new AdminAuthorizationManager(publisher, false);
        assertThat(mgr.authorize(principal(), ctx("GET", "/login")).isGranted()).isTrue();
    }

    @Test
    void resolvesByPrincipalRoleNames() {
        when(publisher.effective(any())).thenReturn(
                new AdminEffectivePermissionsDto("gov", true, List.of("manage-clients")));
        final AdminAuthorizationManager mgr = new AdminAuthorizationManager(publisher, false);
        mgr.authorize(principal("client-manager", "auditor"), ctx("POST", "/admin/realms/gov/clients"));
        final var captor = org.mockito.ArgumentCaptor.forClass(AdminEffectivePermissionsRef.class);
        verify(publisher).effective(captor.capture());
        assertThat(captor.getValue().realmId()).isEqualTo("gov");
        assertThat(captor.getValue().roleNames()).contains("client-manager", "auditor");
    }

    @Test
    void realmFromPath_parsesRealmScopedPaths() {
        assertThat(AdminAuthorizationManager.realmFromPath("/admin/realms/gov/users")).isEqualTo("gov");
        assertThat(AdminAuthorizationManager.realmFromPath("/admin/audit/config")).isNull();
    }

    @Test
    void aPasswordLoginsFactorAuthority_isNeverPassedAsARoleName_norPartOfTheCacheKey() {
        when(publisher.effective(any())).thenReturn(new AdminEffectivePermissionsDto("gov", true, List.of()));
        final AdminAuthorizationManager mgr = new AdminAuthorizationManager(publisher, false);
        final Authentication password = UsernamePasswordAuthenticationToken.authenticated("u-1", null, List.of(
                new org.springframework.security.core.authority.SimpleGrantedAuthority("auditor_gov"),
                org.springframework.security.core.authority.FactorGrantedAuthority.fromAuthority(
                        org.springframework.security.core.authority.FactorGrantedAuthority.PASSWORD_AUTHORITY)));
        final Authentication magicLink = UsernamePasswordAuthenticationToken.authenticated("u-1", null, List.of(
                new org.springframework.security.core.authority.SimpleGrantedAuthority("auditor_gov")));

        mgr.authorize(() -> password, ctx("POST", "/admin/realms/gov/users"));
        mgr.authorize(() -> magicLink, ctx("POST", "/admin/realms/gov/users"));

        final var captor = org.mockito.ArgumentCaptor.forClass(AdminEffectivePermissionsRef.class);
        // One resolution: both sign-ins have the same roles, so they share the cache entry.
        verify(publisher, times(1)).effective(captor.capture());
        assertThat(captor.getValue().roleNames()).containsExactly("auditor_gov");
    }

    @Test
    void aFactorAuthority_neverMakesAnAdmin() {
        final Authentication auth = UsernamePasswordAuthenticationToken.authenticated("u-1", null, List.of(
                org.springframework.security.core.authority.FactorGrantedAuthority.fromFactor("admin_master")));
        assertThat(RealmAdminAuthorities.isMasterAdmin(auth)).isFalse();
        assertThat(RealmAdminAuthorities.isAdminOfAny(auth)).isFalse();
        assertThat(RealmAdminAuthorities.isAdminOf(auth, "master")).isFalse();
    }
}
