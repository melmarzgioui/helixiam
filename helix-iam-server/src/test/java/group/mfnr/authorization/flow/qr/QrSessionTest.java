package group.mfnr.authorization.flow.qr;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Helix IAM E4.2: the cross-device QR-login session is a single-use state machine — PENDING until
 * the enrolled phone confirms, with a rotating short-lived token (every 30s) inside a 5-minute
 * window to defeat QR capture/replay, and a one-shot consume so a CONFIRMED session logs in exactly
 * once. The phone needs the rotating token to confirm; only the browser holding the session id
 * server-side can consume (anti-hijack). This is the pure lifecycle; the store + SSE wrap it.
 */
class QrSessionTest {

    private static final long TTL = 300_000L;       // 5 minutes
    private static final long ROTATE = 30_000L;     // 30 seconds

    private QrSession session(final long createdAt) {
        return new QrSession("sess-1", createdAt, TTL, ROTATE, "tok-0");
    }

    @Test
    void startsPendingWithItsInitialToken() {
        final QrSession s = session(0);
        assertThat(s.status()).isEqualTo(QrSession.Status.PENDING);
        assertThat(s.currentToken()).isEqualTo("tok-0");
    }

    @Test
    void needsRotationOnlyAfterTheRotationInterval() {
        final QrSession s = session(0);
        assertThat(s.needsRotation(ROTATE - 1)).isFalse();
        assertThat(s.needsRotation(ROTATE)).isTrue();

        s.rotate("tok-1", ROTATE);
        assertThat(s.currentToken()).isEqualTo("tok-1");
        assertThat(s.needsRotation(ROTATE + 1)).isFalse();
    }

    @Test
    void isExpiredAtTheEndOfTheTtlWindow() {
        final QrSession s = session(1_000);
        assertThat(s.isExpired(1_000 + TTL - 1)).isFalse();
        assertThat(s.isExpired(1_000 + TTL)).isTrue();
    }

    @Test
    void confirmSucceedsForTheCurrentTokenAndBindsTheUser() {
        final QrSession s = session(0);
        final boolean ok = s.confirm("user-7", "tok-0", 1_000);

        assertThat(ok).isTrue();
        assertThat(s.status()).isEqualTo(QrSession.Status.CONFIRMED);
        assertThat(s.userId()).isEqualTo("user-7");
    }

    @Test
    void confirmRejectsAStaleOrWrongToken() {
        final QrSession s = session(0);
        s.rotate("tok-1", ROTATE);

        assertThat(s.confirm("user-7", "tok-0", ROTATE + 1)).isFalse();
        assertThat(s.status()).isEqualTo(QrSession.Status.PENDING);
    }

    @Test
    void confirmExpiresAnOldSessionInsteadOfConfirming() {
        final QrSession s = session(0);
        assertThat(s.confirm("user-7", "tok-0", TTL + 1)).isFalse();
        assertThat(s.status()).isEqualTo(QrSession.Status.EXPIRED);
    }

    @Test
    void confirmIsRejectedOnceAlreadyConfirmed() {
        final QrSession s = session(0);
        s.confirm("user-7", "tok-0", 1_000);
        assertThat(s.confirm("attacker", "tok-0", 2_000)).isFalse();
        assertThat(s.userId()).isEqualTo("user-7"); // unchanged
    }

    @Test
    void consumeReturnsTheUserOnceThenIsSingleUse() {
        final QrSession s = session(0);
        s.confirm("user-7", "tok-0", 1_000);

        assertThat(s.consume()).isEqualTo("user-7");
        assertThat(s.status()).isEqualTo(QrSession.Status.CONSUMED);
        assertThat(s.consume()).isNull(); // second consume yields nothing
    }

    @Test
    void consumeBeforeConfirmYieldsNothing() {
        assertThat(session(0).consume()).isNull();
    }
}
