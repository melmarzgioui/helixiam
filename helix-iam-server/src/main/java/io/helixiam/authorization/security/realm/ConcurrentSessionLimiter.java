package io.helixiam.authorization.security.realm;

import io.helixiam.authorization.amqp.realm.RealmSettingsDto;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.security.core.session.SessionInformation;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.stereotype.Component;

import java.util.Comparator;
import java.util.List;

/**
 * Auth-hardening (feature 6): enforces a per-realm cap on the number of concurrent SSO sessions a single
 * user may hold, at SSO-session establishment (login success). Reuses the existing Spring
 * {@link SessionRegistry} (the same registry the SAS uses for the {@code sid}).
 *
 * <p>{@code maxConcurrentSessions == 0} means unlimited (the default — login path unchanged). When the cap
 * is reached the realm policy decides: {@code evictOldest} expires the oldest existing session(s) to make
 * room, otherwise the new login is denied (the caller raises an error). Never throws.
 */
@Component
public class ConcurrentSessionLimiter {

    private static final Logger LOG = LogManager.getLogger(ConcurrentSessionLimiter.class);

    private final SessionRegistry sessionRegistry;
    private final RealmSettingsResolver resolver;

    public ConcurrentSessionLimiter(final SessionRegistry sessionRegistry, final RealmSettingsResolver resolver) {
        this.sessionRegistry = sessionRegistry;
        this.resolver = resolver;
    }

    /** Outcome of the concurrent-session check at login. */
    public enum Outcome {
        /** Under the cap (or unlimited) — proceed. */
        ALLOWED,
        /** Cap was hit and the oldest session(s) were evicted — proceed. */
        EVICTED_OLDEST,
        /** Cap was hit and the realm denies new logins — block this login. */
        DENIED
    }

    /**
     * Applies the realm's concurrent-session policy for {@code principal}. Counts the principal's existing
     * non-expired sessions in the registry; the just-created session is excluded via {@code currentSessionId}.
     *
     * @param realmId          the realm whose policy applies
     * @param principal        the registry principal (Spring caches sessions per principal object/name)
     * @param currentSessionId the new session's id (excluded from the count); may be {@code null}
     */
    public Outcome enforceOnLogin(final String realmId, final Object principal, final String currentSessionId) {
        try {
            final RealmSettingsDto settings = resolver.get(realmId);
            final int max = settings.maxConcurrentSessions();
            if (max <= 0 || principal == null) {
                return Outcome.ALLOWED;
            }
            // Existing sessions for this principal, oldest first, excluding the brand-new one.
            final List<SessionInformation> existing = sessionRegistry.getAllSessions(principal, false).stream()
                    .filter(s -> currentSessionId == null || !currentSessionId.equals(s.getSessionId()))
                    .sorted(Comparator.comparing(SessionInformation::getLastRequest))
                    .toList();

            // Allowing the new session means existing must be < max.
            final int overBy = existing.size() - (max - 1);
            if (overBy <= 0) {
                return Outcome.ALLOWED;
            }
            if (!settings.concurrentSessionEvictOldest()) {
                LOG.info("Concurrent-session cap ({}) reached for principal in realm {}, denying new login", max, realmId);
                return Outcome.DENIED;
            }
            existing.stream().limit(overBy).forEach(s -> {
                s.expireNow();
                LOG.info("Evicted oldest session {} to honour concurrent-session cap {} in realm {}",
                        s.getSessionId(), max, realmId);
            });
            return Outcome.EVICTED_OLDEST;
        } catch (final RuntimeException e) {
            // Never let concurrent-session enforcement break login.
            LOG.warn("Concurrent-session enforcement failed for realm {}, allowing: {}", realmId, e.getMessage());
            return Outcome.ALLOWED;
        }
    }
}
