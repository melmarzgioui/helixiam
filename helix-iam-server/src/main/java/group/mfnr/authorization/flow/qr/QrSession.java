package group.mfnr.authorization.flow.qr;

/**
 * Helix IAM E4.2: cross-device QR-login session lifecycle. A browser opens a PENDING session; the QR
 * encodes a token that rotates every {@code rotationMillis} (defeating capture/replay) within a
 * {@code ttlMillis} window. The enrolled phone confirms with the current token, binding the user;
 * the browser — the only party holding the session id server-side — then consumes it exactly once to
 * complete login (anti-hijack: the phone only ever has the rotating token, never the consume).
 *
 * Pure state machine (clock passed in as {@code now} millis) so it is fully unit-testable; the store
 * and SSE delivery wrap it.
 */
public class QrSession {

    public enum Status { PENDING, CONFIRMED, CONSUMED, EXPIRED }

    private final String id;
    private final long createdAt;
    private final long ttlMillis;
    private final long rotationMillis;

    private String token;
    private long tokenIssuedAt;
    private Status status = Status.PENDING;
    private String userId;

    public QrSession(final String id, final long createdAt, final long ttlMillis,
                     final long rotationMillis, final String initialToken) {
        this.id = id;
        this.createdAt = createdAt;
        this.ttlMillis = ttlMillis;
        this.rotationMillis = rotationMillis;
        this.token = initialToken;
        this.tokenIssuedAt = createdAt;
    }

    public String id() {
        return id;
    }

    public Status status() {
        return status;
    }

    public String userId() {
        return userId;
    }

    public String currentToken() {
        return token;
    }

    public boolean isExpired(final long now) {
        return now - createdAt >= ttlMillis;
    }

    public boolean needsRotation(final long now) {
        return now - tokenIssuedAt >= rotationMillis;
    }

    /** Replace the QR token (the caller supplies a fresh single-use token). */
    public void rotate(final String newToken, final long now) {
        this.token = newToken;
        this.tokenIssuedAt = now;
    }

    /**
     * Confirm from the enrolled phone: only a PENDING, non-expired session presenting the current
     * token binds the user and moves to CONFIRMED. A stale token or an expired window is rejected.
     */
    public boolean confirm(final String confirmingUserId, final String presentedToken, final long now) {
        if (status != Status.PENDING) {
            return false;
        }
        if (isExpired(now)) {
            status = Status.EXPIRED;
            return false;
        }
        if (!token.equals(presentedToken)) {
            return false;
        }
        this.userId = confirmingUserId;
        this.status = Status.CONFIRMED;
        return true;
    }

    /** Single-use: returns the bound user id once for a CONFIRMED session, then null. */
    public String consume() {
        if (status != Status.CONFIRMED) {
            return null;
        }
        status = Status.CONSUMED;
        return userId;
    }
}
