package io.helixiam.authorization.session;

import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Helix IAM SSO P4: rolls every client authorization sharing one {@code sid} up into a single SSO session
 * (one browser login spanning N clients). Authorizations with no {@code sid} (service accounts /
 * client_credentials) are not SSO sessions and are dropped. Fully-expired authorizations are dropped, and
 * the same app is shown once per session (Sessions v2).
 */
class SsoSessionRollupTest {

    /** A fixed "now" far in the past so the tiny epoch-second fixtures below count as live (not expired). */
    private static final Instant AT_EPOCH = Instant.EPOCH;

    private static SsoSessionRollup.Entry entry(final String sid, final String client, final long issued, final long expires) {
        return new SsoSessionRollup.Entry(sid, "authz-" + client + "-" + issued, client, "alice", "authorization_code",
                List.of("openid"), Instant.ofEpochSecond(issued), Instant.ofEpochSecond(expires));
    }

    @Test
    void groupsAuthorizationsBySid_intoOneSessionPerLogin() {
        final List<SsoSession> sessions = SsoSessionRollup.assemble(List.of(
                entry("sid-A", "spa-app", 100, 900),
                entry("sid-A", "dashboard", 200, 800),
                entry("sid-B", "spa-app", 300, 700)), AT_EPOCH);

        assertEquals(2, sessions.size());
        final SsoSession a = sessions.stream().filter(s -> s.ssoSessionId().equals("sid-A")).findFirst().orElseThrow();
        assertEquals("alice", a.principalName());
        assertEquals(List.of("dashboard", "spa-app"), a.clients().stream().map(SsoSession.ClientInSession::clientId).sorted().toList());
        assertEquals(Instant.ofEpochSecond(200), a.issuedAt(), "signed in = most recent authentication in the session");
        assertEquals(Instant.ofEpochSecond(900), a.expiresAt(), "session end = latest expiry");
    }

    @Test
    void dropsAuthorizationsWithoutASid() {
        final List<SsoSession> sessions = SsoSessionRollup.assemble(List.of(
                entry(null, "svc-account", 100, 900),
                entry("", "svc-2", 100, 900),
                entry("sid-A", "spa-app", 100, 900)), AT_EPOCH);

        assertEquals(1, sessions.size());
        assertEquals("sid-A", sessions.get(0).ssoSessionId());
    }

    @Test
    void emptyInput_yieldsNoSessions() {
        assertTrue(SsoSessionRollup.assemble(List.of()).isEmpty());
    }

    @Test
    void dropsExpiredAuthorizations_soSignedInReflectsTheLiveLogin() {
        final Instant now = Instant.ofEpochSecond(10_000);
        final List<SsoSession> sessions = SsoSessionRollup.assemble(List.of(
                entry("sid-A", "helix-console", 1_000, 5_000),     // expired (5000 < now)
                entry("sid-A", "helix-console", 9_000, 12_600)),   // live   (12600 > now)
                now);

        assertEquals(1, sessions.size());
        final SsoSession a = sessions.get(0);
        assertEquals(Instant.ofEpochSecond(9_000), a.issuedAt(), "signed in = the live login, not the expired one");
        assertEquals(1, a.clients().size(), "the same app appears once");
        assertEquals("helix-console", a.clients().get(0).clientId());
    }

    @Test
    void dedupsAppsByClientId_forMultipleLiveAuthorizationsOfTheSameClient() {
        final List<SsoSession> sessions = SsoSessionRollup.assemble(List.of(
                entry("sid-A", "helix-console", 100, 900),
                entry("sid-A", "helix-console", 200, 800)), AT_EPOCH);

        assertEquals(1, sessions.size());
        assertEquals(1, sessions.get(0).clients().size(), "same app shown once, not duplicated");
    }

    @Test
    void fullyExpiredSession_isDropped() {
        final Instant now = Instant.ofEpochSecond(10_000);
        assertTrue(SsoSessionRollup.assemble(List.of(entry("sid-A", "helix-console", 1_000, 5_000)), now).isEmpty());
    }
}
