/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.observability;

import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.search.Search;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Helix IAM observability: a compact JSON metrics summary for the admin console's Health screen. The raw
 * Prometheus exposition stays at {@code /actuator/prometheus} for scrapers; this endpoint exposes only the
 * handful of derived figures the console renders (login totals + success rate, MFA + token + admin-write
 * counts), optionally scoped to one realm.
 *
 * <p>Returns a {@link ResponseEntity} and never throws — on the admin surface a thrown exception is dispatched
 * to /error, which 302-redirects to the login page (the recurring admin /error gotcha). A degraded/empty
 * registry simply yields zeroes.
 */
@RestController
@RequestMapping("/admin/metrics")
public class MetricsSummaryController {

    private final MeterRegistry registry;

    public MetricsSummaryController(final MeterRegistry registry) {
        this.registry = registry;
    }

    /** Compact metrics summary. {@code ?realm=} optionally scopes the figures to a single realm. */
    @GetMapping("/summary")
    public ResponseEntity<Map<String, Object>> summary(@RequestParam(required = false) final String realm) {
        final Map<String, Object> body = new LinkedHashMap<>();
        try {
            final double loginSuccess = sum(MetricNames.LOGIN_TOTAL, realm, "outcome", "success");
            final double loginFailure = sum(MetricNames.LOGIN_TOTAL, realm, "outcome", "failure");
            final double loginTotal = loginSuccess + loginFailure;

            body.put("realm", realm); // null = all realms
            body.put("loginSuccess", (long) loginSuccess);
            body.put("loginFailure", (long) loginFailure);
            body.put("loginTotal", (long) loginTotal);
            // success rate as a 0..1 fraction; null when there is nothing to divide.
            body.put("loginSuccessRate", loginTotal > 0 ? round(loginSuccess / loginTotal) : null);

            body.put("mfaSuccess", (long) sum(MetricNames.MFA_CHALLENGE_TOTAL, realm, "outcome", "success"));
            body.put("mfaFailure", (long) sum(MetricNames.MFA_CHALLENGE_TOTAL, realm, "outcome", "failure"));
            body.put("tokensIssued", (long) sum(MetricNames.TOKENS_ISSUED_TOTAL, realm, null, null));
            body.put("adminWrites", (long) sum(MetricNames.ADMIN_WRITE_TOTAL, realm, null, null));
        } catch (final RuntimeException e) {
            // Degrade gracefully — never surface a 500 (which would /error-redirect on the admin chain).
            body.put("error", "metrics unavailable");
        }
        return ResponseEntity.ok(body);
    }

    /**
     * Sum the count across all series of {@code name}, optionally filtered by {@code realm} and one extra
     * {@code tagKey=tagValue}. Aggregating across the other (unfiltered) tags keeps the console payload small.
     */
    private double sum(final String name, final String realm, final String tagKey, final String tagValue) {
        Search search = registry.find(name);
        if (realm != null && !realm.isBlank()) {
            search = search.tag("realm", realm);
        }
        if (tagKey != null && tagValue != null) {
            search = search.tag(tagKey, tagValue);
        }
        double total = 0d;
        for (final Counter c : search.counters()) {
            total += c.count();
        }
        return total;
    }

    private static double round(final double v) {
        return Math.round(v * 10000d) / 10000d;
    }

    /** Mirror of {@link HelixMetrics}' counter names (package-private constants kept in one place). */
    private static final class MetricNames {
        static final String LOGIN_TOTAL = HelixMetrics.LOGIN_TOTAL;
        static final String TOKENS_ISSUED_TOTAL = HelixMetrics.TOKENS_ISSUED_TOTAL;
        static final String MFA_CHALLENGE_TOTAL = HelixMetrics.MFA_CHALLENGE_TOTAL;
        static final String ADMIN_WRITE_TOTAL = HelixMetrics.ADMIN_WRITE_TOTAL;

        private MetricNames() {
        }
    }
}
