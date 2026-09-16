package group.mfnr.authorization.security.realm;

import group.mfnr.authorization.amqp.realm.RealmSettingsDto;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.session.SessionInformation;
import org.springframework.security.core.session.SessionRegistry;

import java.util.Date;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/** Auth-hardening (feature 6): per-realm concurrent-session enforcement over the Spring SessionRegistry. */
class ConcurrentSessionLimiterTest {

    private SessionRegistry registry;
    private RealmSettingsResolver resolver;
    private ConcurrentSessionLimiter limiter;

    @BeforeEach
    void setUp() {
        registry = mock(SessionRegistry.class);
        resolver = mock(RealmSettingsResolver.class);
        limiter = new ConcurrentSessionLimiter(registry, resolver);
    }

    private RealmSettingsDto settings(final int max, final boolean evictOldest) {
        return new RealmSettingsDto("gov", "gov", null, 3600, 5_184_000, false, false, 12, true,
                1_800, 36_000, false, 2_592_000,
                false, 5, 900, 900, false,
                false, false, false, false, false, 0,
                false, "none", null, null, max, evictOldest, false, 40, 70, "allow", "step_up", "deny",
                null, null, null, null, null, true);
    }

    private SessionInformation session(final String id, final long ageMillis) {
        return new SessionInformation("alice", id, new Date(System.currentTimeMillis() - ageMillis));
    }

    @Test
    void unlimited_whenMaxIsZero() {
        when(resolver.get("gov")).thenReturn(settings(0, true));
        assertThat(limiter.enforceOnLogin("gov", "alice", "new"))
                .isEqualTo(ConcurrentSessionLimiter.Outcome.ALLOWED);
        verify(registry, never()).getAllSessions(org.mockito.ArgumentMatchers.any(), org.mockito.ArgumentMatchers.anyBoolean());
    }

    @Test
    void allowed_whenUnderCap() {
        when(resolver.get("gov")).thenReturn(settings(2, true));
        when(registry.getAllSessions("alice", false)).thenReturn(List.of(session("s1", 1000), session("new", 0)));
        // existing (excluding "new") = 1, cap 2 → allowed.
        assertThat(limiter.enforceOnLogin("gov", "alice", "new"))
                .isEqualTo(ConcurrentSessionLimiter.Outcome.ALLOWED);
    }

    @Test
    void evictsOldest_whenOverCap_andPolicyAllows() {
        when(resolver.get("gov")).thenReturn(settings(1, true));
        final SessionInformation oldest = session("old", 5000);
        final SessionInformation newer = session("mid", 1000);
        when(registry.getAllSessions("alice", false)).thenReturn(List.of(newer, oldest, session("new", 0)));

        assertThat(limiter.enforceOnLogin("gov", "alice", "new"))
                .isEqualTo(ConcurrentSessionLimiter.Outcome.EVICTED_OLDEST);
        // cap 1, so both existing pre-login sessions must be expired (oldest first).
        assertThat(oldest.isExpired()).isTrue();
        assertThat(newer.isExpired()).isTrue();
    }

    @Test
    void denies_whenOverCap_andPolicyDenies() {
        when(resolver.get("gov")).thenReturn(settings(1, false));
        final SessionInformation existing = session("s1", 2000);
        when(registry.getAllSessions("alice", false)).thenReturn(List.of(existing, session("new", 0)));

        assertThat(limiter.enforceOnLogin("gov", "alice", "new"))
                .isEqualTo(ConcurrentSessionLimiter.Outcome.DENIED);
        assertThat(existing.isExpired()).isFalse();
    }

    @Test
    void failsOpen_whenResolverThrows() {
        when(resolver.get("gov")).thenThrow(new RuntimeException("amqp down"));
        assertThat(limiter.enforceOnLogin("gov", "alice", "new"))
                .isEqualTo(ConcurrentSessionLimiter.Outcome.ALLOWED);
    }
}
