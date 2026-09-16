/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.observability;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;

import java.util.Arrays;
import java.util.List;
import java.util.Set;

/**
 * Helix IAM observability: meters every mutating {@code /admin/**} request once it completes, mirroring the
 * audit interceptor (reads — GET/HEAD/OPTIONS — are not metered). Tags by realm + method + outcome only, so
 * cardinality stays bounded. Never throws — {@link HelixMetrics} swallows internally and the handler does no
 * other work, so it cannot break the admin response (avoids the /error 302-to-login gotcha).
 */
@Component
public class MetricsAdminInterceptor implements HandlerInterceptor {

    private static final Set<String> MUTATING = Set.of("POST", "PUT", "PATCH", "DELETE");

    private final HelixMetrics metrics;

    public MetricsAdminInterceptor(final HelixMetrics metrics) {
        this.metrics = metrics;
    }

    @Override
    public void afterCompletion(final HttpServletRequest request, final HttpServletResponse response,
                                final Object handler, final Exception ex) {
        final String method = request.getMethod().toUpperCase();
        if (!MUTATING.contains(method)) {
            return;
        }
        final int status = ex != null && response.getStatus() < 400 ? 500 : response.getStatus();
        metrics.recordAdminWrite(realmOf(request.getRequestURI()), method, outcome(status));
    }

    /** Realm from {@code /admin/realms/{realm}/...}, else {@code null} (rendered as {@code unknown}). */
    private static String realmOf(final String path) {
        if (path == null) {
            return null;
        }
        final List<String> seg = Arrays.stream(path.split("/")).filter(s -> !s.isBlank()).toList();
        return seg.size() >= 3 && "admin".equals(seg.get(0)) && "realms".equals(seg.get(1)) ? seg.get(2) : null;
    }

    private static String outcome(final int status) {
        if (status < 400) {
            return "success";
        }
        return status < 500 ? "denied" : "failure";
    }
}
