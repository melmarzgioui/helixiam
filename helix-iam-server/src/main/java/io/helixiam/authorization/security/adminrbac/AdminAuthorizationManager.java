/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.security.adminrbac;

import io.helixiam.authorization.amqp.adminrbac.AdminEffectivePermissionsDto;
import io.helixiam.authorization.amqp.adminrbac.AdminEffectivePermissionsRef;
import io.helixiam.authorization.amqp.adminrbac.AdminRbacPublisher;
import jakarta.servlet.http.HttpServletRequest;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Supplier;

/**
 * Helix IAM: fine-grained admin authorization for {@code /admin/**}. For an authenticated admin principal it
 * resolves the required permission for the matched route group ({@link AdminRoutePermissions}) and checks it
 * against the principal's effective admin permissions, resolved over the queue ({@link AdminRbacPublisher})
 * from the realm role→permission grants.
 * <p>
 * STRICTLY ADDITIVE + DEFAULT-SAFE (see the feature contract):
 * <ul>
 *   <li>No-op (grant) when {@code helix.admin.dev-open=true} — the e2e dev-open path is unaffected.</li>
 *   <li>DENY when there is no authenticated (non-anonymous) principal — this manager is the SOLE
 *       authorization rule for {@code /admin/**} (a later {@code anyRequest().authenticated()} never runs,
 *       because the first matching {@code authorizeHttpRequests} rule wins), so it enforces login itself.</li>
 *   <li>No-op (grant) when the realm's admin-RBAC model is empty ({@code modelConfigured=false}) — a realm
 *       with no grants behaves exactly as today (any authenticated admin is allowed).</li>
 *   <li>If the AMQP resolution fails/returns null, fail OPEN (grant) so an RBAC outage can never lock admins
 *       out of an otherwise-working console — enforcement is a guard, not the only gate.</li>
 * </ul>
 */
public class AdminAuthorizationManager implements AuthorizationManager<RequestAuthorizationContext> {

    private static final Logger LOG = LogManager.getLogger(AdminAuthorizationManager.class);
    private static final long CACHE_TTL_MS = 30_000L;

    private final AdminRbacPublisher publisher;
    private final boolean devOpen;
    private final Map<String, Cached> cache = new ConcurrentHashMap<>();

    public AdminAuthorizationManager(final AdminRbacPublisher publisher, final boolean devOpen) {
        this.publisher = publisher;
        this.devOpen = devOpen;
    }

    @Override
    public AuthorizationDecision check(final Supplier<Authentication> authentication,
                                       final RequestAuthorizationContext context) {
        if (devOpen) {
            return new AuthorizationDecision(true); // LOCAL-DEV: admin API is wide open, never enforce.
        }
        final HttpServletRequest request = context.getRequest();
        final String path = request.getRequestURI();
        final String contextPath = request.getContextPath();
        final String adminPath = (contextPath != null && !contextPath.isEmpty() && path.startsWith(contextPath))
                ? path.substring(contextPath.length()) : path;

        final Optional<String> required = AdminRoutePermissions.required(adminPath, request.getMethod());
        if (required.isEmpty()) {
            return new AuthorizationDecision(true); // not an /admin route — nothing to enforce here.
        }

        final Authentication auth = authentication.get();
        if (auth == null || !auth.isAuthenticated() || auth instanceof AnonymousAuthenticationToken) {
            // This manager is the SOLE authorization rule for /admin/** (the later anyRequest().authenticated()
            // never runs, because the first matching authorizeHttpRequests rule wins). So it must enforce
            // authentication itself — an anonymous/unauthenticated caller is DENIED, never granted.
            return new AuthorizationDecision(false);
        }

        final String realmId = realmFromPath(adminPath);
        if (realmId == null) {
            // Realm-independent admin path (e.g. /admin/audit/**) — require the model to grant the permission,
            // but with no realm we cannot resolve grants; default-safe = allow (matches today).
            return new AuthorizationDecision(true);
        }

        final List<String> roleNames = auth.getAuthorities().stream()
                .map(a -> a.getAuthority())
                .filter(s -> s != null && !s.isBlank())
                .distinct().toList();

        final AdminEffectivePermissionsDto eff = resolve(realmId, roleNames);
        if (eff == null || !eff.modelConfigured()) {
            return new AuthorizationDecision(true); // unconfigured realm OR resolution failure → fail open.
        }
        final boolean granted = eff.permissions().contains(AdminRoutePermissions.REALM_ADMIN)
                || eff.permissions().contains(required.get());
        if (!granted) {
            LOG.debug("Admin RBAC denied {} {} (needs {}) for roles {} in realm {}",
                    request.getMethod(), adminPath, required.get(), roleNames, realmId);
        }
        return new AuthorizationDecision(granted);
    }

    private AdminEffectivePermissionsDto resolve(final String realmId, final List<String> roleNames) {
        final String key = realmId + "::" + String.join(",", roleNames.stream().sorted().toList());
        final long now = System.currentTimeMillis();
        final Cached hit = cache.get(key);
        if (hit != null && now - hit.at < CACHE_TTL_MS) {
            return hit.value;
        }
        try {
            final AdminEffectivePermissionsDto value =
                    publisher.effective(new AdminEffectivePermissionsRef(realmId, roleNames));
            cache.put(key, new Cached(value, now));
            return value;
        } catch (final RuntimeException ex) {
            LOG.warn("Admin RBAC resolution failed for realm {} — failing open", realmId, ex);
            return null;
        }
    }

    /** {@code /admin/realms/{realmId}/...} → realmId, or null when the path is not realm-scoped. */
    static String realmFromPath(final String adminPath) {
        final String[] seg = adminPath.startsWith("/") ? adminPath.substring(1).split("/") : adminPath.split("/");
        if (seg.length >= 3 && "admin".equals(seg[0]) && "realms".equals(seg[1])) {
            return seg[2];
        }
        return null;
    }

    private record Cached(AdminEffectivePermissionsDto value, long at) {
    }
}
