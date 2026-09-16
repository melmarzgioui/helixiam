package group.mfnr.authorization.security.realm;

import group.mfnr.authorization.amqp.realm.RealmAdminPublisher;
import group.mfnr.authorization.amqp.realm.RealmSettingsDto;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Helix IAM SSO P3: short-TTL cache over the realm-settings AMQP lookup, so login-time SSO-policy
 * enforcement never does a round-trip per request, and never breaks when the lookup fails.
 */
class RealmSettingsResolverTest {

    private static long now = 0L;
    private final RealmAdminPublisher publisher = mock(RealmAdminPublisher.class);
    private final RealmSettingsResolver resolver = new RealmSettingsResolver(publisher, 1_000L, () -> now);

    private static RealmSettingsDto dto(final String realm, final int idle) {
        return new RealmSettingsDto(realm, realm, null, 3600, 5_184_000, false, false, 12, true, idle, 36_000, false, 2_592_000,
                false, 5, 900, 900, false,
                false, false, false, false, false, 0,
                false, "none", null, null, 0, true, false, 40, 70, "allow", "step_up", "deny",
                null, null, null, null, null, true);
    }

    @Test
    void cachesWithinTtl_thenRefreshesAfter() {
        now = 0L;
        when(publisher.get("gov")).thenReturn(dto("gov", 600));

        assertEquals(600, resolver.get("gov").ssoSessionIdleTimeoutSeconds());
        assertEquals(600, resolver.get("gov").ssoSessionIdleTimeoutSeconds()); // cache hit
        verify(publisher, times(1)).get("gov");

        now = 2_000L; // past the 1s TTL
        resolver.get("gov");
        verify(publisher, times(2)).get("gov");
    }

    @Test
    void fallsBackToDefaults_whenLookupFails() {
        now = 0L;
        when(publisher.get("broken")).thenThrow(new RuntimeException("amqp down"));

        final RealmSettingsDto fallback = resolver.get("broken");

        assertEquals(RealmSettingsResolver.DEFAULT_IDLE_SECONDS, fallback.ssoSessionIdleTimeoutSeconds());
        assertEquals(RealmSettingsResolver.DEFAULT_MAX_LIFETIME_SECONDS, fallback.ssoSessionMaxLifetimeSeconds());
    }

    @Test
    void exists_trueForKnownRealm_falseForUnknown_bothCached() {
        now = 0L;
        // The oracle is the raw existence check (realm-config row), NOT get() which synthesizes defaults
        // for any id — so a bogus realm must answer false.
        when(publisher.exists("real")).thenReturn(true);
        when(publisher.exists("ghost")).thenReturn(false); // subscriber says: no such realm

        org.junit.jupiter.api.Assertions.assertTrue(resolver.exists("real"));
        org.junit.jupiter.api.Assertions.assertFalse(resolver.exists("ghost"));
        // both cached within the TTL — no second AMQP round-trip (negative results cached too, so a bogus
        // realm sprayed at the discovery endpoint can't hammer the queue)
        resolver.exists("real");
        resolver.exists("ghost");
        verify(publisher, times(1)).exists("real");
        verify(publisher, times(1)).exists("ghost");
    }

    @Test
    void exists_falseForNullAnswer() {
        now = 0L;
        when(publisher.exists("ghost2")).thenReturn(null); // AMQP null → treat as not existing
        org.junit.jupiter.api.Assertions.assertFalse(resolver.exists("ghost2"));
    }

    @Test
    void exists_failsOpen_whenLookupErrors() {
        now = 0L;
        when(publisher.exists("broken")).thenThrow(new RuntimeException("amqp down"));
        // a lookup failure must NOT 404 a possibly-valid realm — fail open (treat as existing)
        org.junit.jupiter.api.Assertions.assertTrue(resolver.exists("broken"));
    }

    @Test
    void defaults_haveRegistrationEnabledTrue() {
        // No publisher row → defaults(realm) is returned; registration is on by default.
        when(publisher.get("nope")).thenReturn(null);
        assertThat(resolver.get("nope").registrationEnabled()).isTrue();
    }
}
