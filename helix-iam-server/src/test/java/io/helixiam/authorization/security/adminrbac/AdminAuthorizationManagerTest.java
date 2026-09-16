package io.helixiam.authorization.security.adminrbac;

import io.helixiam.authorization.amqp.adminrbac.AdminEffectivePermissionsDto;
import io.helixiam.authorization.amqp.adminrbac.AdminEffectivePermissionsRef;
import io.helixiam.authorization.amqp.adminrbac.AdminRbacPublisher;
import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
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
    void devOpen_alwaysGrants_neverCallsPublisher() {
        final AdminAuthorizationManager mgr = new AdminAuthorizationManager(publisher, true);
        assertThat(mgr.check(principal("anything"), ctx("DELETE", "/admin/realms/gov/users/u-9")).isGranted()).isTrue();
        verify(publisher, times(0)).effective(any());
    }

    @Test
    void unconfiguredRealm_isDefaultSafeAllow() {
        when(publisher.effective(any())).thenReturn(new AdminEffectivePermissionsDto("gov", false, List.of()));
        final AdminAuthorizationManager mgr = new AdminAuthorizationManager(publisher, false);
        assertThat(mgr.check(principal("auditor"), ctx("POST", "/admin/realms/gov/users")).isGranted()).isTrue();
    }

    @Test
    void grantsWhenPrincipalHasRequiredPermission() {
        when(publisher.effective(any())).thenReturn(
                new AdminEffectivePermissionsDto("gov", true, List.of("manage-users")));
        final AdminAuthorizationManager mgr = new AdminAuthorizationManager(publisher, false);
        assertThat(mgr.check(principal("user-admin"), ctx("POST", "/admin/realms/gov/users")).isGranted()).isTrue();
    }

    @Test
    void deniesWhenPrincipalLacksRequiredPermission() {
        when(publisher.effective(any())).thenReturn(
                new AdminEffectivePermissionsDto("gov", true, List.of("view-users")));
        final AdminAuthorizationManager mgr = new AdminAuthorizationManager(publisher, false);
        // POST (write) needs manage-users; principal only has view-users.
        assertThat(mgr.check(principal("auditor"), ctx("POST", "/admin/realms/gov/users")).isGranted()).isFalse();
    }

    @Test
    void viewerCanReadButNotWrite() {
        when(publisher.effective(any())).thenReturn(
                new AdminEffectivePermissionsDto("gov", true, List.of("view-users")));
        final AdminAuthorizationManager mgr = new AdminAuthorizationManager(publisher, false);
        assertThat(mgr.check(principal("auditor"), ctx("GET", "/admin/realms/gov/users")).isGranted()).isTrue();
        assertThat(mgr.check(principal("auditor"), ctx("DELETE", "/admin/realms/gov/users/u-9")).isGranted()).isFalse();
    }

    @Test
    void realmAdminGrantsEverything() {
        when(publisher.effective(any())).thenReturn(
                new AdminEffectivePermissionsDto("gov", true, List.of("realm-admin")));
        final AdminAuthorizationManager mgr = new AdminAuthorizationManager(publisher, false);
        assertThat(mgr.check(principal("superadmin"), ctx("DELETE", "/admin/realms/gov/clients/c-1")).isGranted()).isTrue();
    }

    @Test
    void failsOpenWhenResolutionThrows() {
        when(publisher.effective(any())).thenThrow(new RuntimeException("AMQP down"));
        final AdminAuthorizationManager mgr = new AdminAuthorizationManager(publisher, false);
        assertThat(mgr.check(principal("user-admin"), ctx("POST", "/admin/realms/gov/users")).isGranted()).isTrue();
    }

    @Test
    void nonAdminPath_isNotEnforced() {
        final AdminAuthorizationManager mgr = new AdminAuthorizationManager(publisher, false);
        assertThat(mgr.check(principal(), ctx("GET", "/login")).isGranted()).isTrue();
    }

    @Test
    void resolvesByPrincipalRoleNames() {
        when(publisher.effective(any())).thenReturn(
                new AdminEffectivePermissionsDto("gov", true, List.of("manage-clients")));
        final AdminAuthorizationManager mgr = new AdminAuthorizationManager(publisher, false);
        mgr.check(principal("client-manager", "auditor"), ctx("POST", "/admin/realms/gov/clients"));
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
}
