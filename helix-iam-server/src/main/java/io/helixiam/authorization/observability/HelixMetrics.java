package io.helixiam.authorization.observability;

import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import org.springframework.stereotype.Component;

/**
 * Helix IAM observability: a thin, MeterRegistry-backed facade for the custom IAM metrics. Every public
 * method is wrapped in a try/catch and returns {@code void} so a metrics increment can <strong>never</strong>
 * throw into the authentication / token hot path — the worst case is a missing data point, never a 500 (or,
 * on an admin endpoint, a /error 302-to-login). This is the single place the SecurityConfig / OAuthConfig /
 * MFA / admin hooks call into, so each hook stays a one-liner.
 *
 * <p>Cardinality is deliberately bounded: tags are {@code realm} (a small, operator-controlled set) and a
 * fixed-vocabulary {@code outcome}/{@code grant_type}/{@code method} — <strong>never</strong> a per-user,
 * per-IP or per-client-id value. {@code realm} is normalised to {@code "unknown"} when absent so the series
 * stays bounded even on the realm-agnostic {@code /admin/**} threads.
 *
 * <p>Counters are created lazily and cached by Micrometer (one series per tag-set), so repeated
 * {@code Counter.builder(...).register(registry)} calls return the same meter — cheap on the hot path.
 */
@Component
public class HelixMetrics {

    static final String LOGIN_TOTAL = "helix_login_total";
    static final String TOKENS_ISSUED_TOTAL = "helix_tokens_issued_total";
    static final String MFA_CHALLENGE_TOTAL = "helix_mfa_challenge_total";
    static final String ADMIN_WRITE_TOTAL = "helix_admin_write_total";

    private static final String UNKNOWN = "unknown";

    private final MeterRegistry registry;

    public HelixMetrics(final MeterRegistry registry) {
        this.registry = registry;
    }

    /** Record a login attempt outcome. {@code outcome} is {@code "success"} or {@code "failure"}. */
    public void recordLogin(final String realm, final String outcome) {
        increment(LOGIN_TOTAL, "realm", realm, "outcome", safe(outcome));
    }

    /**
     * Record an issued token, tagged by OAuth2 grant type (e.g. {@code authorization_code},
     * {@code client_credentials}, {@code refresh_token}). Bounded — the grant-type vocabulary is fixed.
     */
    public void recordTokenIssued(final String realm, final String grantType) {
        increment(TOKENS_ISSUED_TOTAL, "realm", realm, "grant_type", safe(grantType));
    }

    /** Record an MFA challenge outcome. {@code outcome} is {@code "success"} or {@code "failure"}. */
    public void recordMfaChallenge(final String realm, final String outcome) {
        increment(MFA_CHALLENGE_TOTAL, "realm", realm, "outcome", safe(outcome));
    }

    /**
     * Record a mutating admin write. {@code method} is the HTTP verb (POST/PUT/PATCH/DELETE) and
     * {@code outcome} is {@code success}/{@code denied}/{@code failure} (bounded vocabulary).
     */
    public void recordAdminWrite(final String realm, final String method, final String outcome) {
        increment(ADMIN_WRITE_TOTAL, "realm", realm, "method", safe(method), "outcome", safe(outcome));
    }

    private void increment(final String name, final String... tags) {
        try {
            // Normalise realm (always the first tag value) to keep cardinality bounded.
            final String[] normalised = tags.clone();
            for (int i = 0; i + 1 < normalised.length; i += 2) {
                if ("realm".equals(normalised[i])) {
                    normalised[i + 1] = safe(normalised[i + 1]);
                }
            }
            Counter.builder(name).tags(normalised).register(registry).increment();
        } catch (final RuntimeException ignored) {
            // A metrics failure must never propagate into the auth / admin path.
        }
    }

    private static String safe(final String value) {
        return value == null || value.isBlank() ? UNKNOWN : value;
    }
}
