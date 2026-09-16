package group.mfnr.authorization.flow.magiclink;

/**
 * Helix IAM: a single-use, TTL-bound passwordless magic-link token bound to a user. Pure (clock
 * passed in) so it is fully unit-testable; the store wraps it.
 */
public class MagicLinkToken {

    public enum Status { PENDING, USED, EXPIRED }

    private final String token;
    private final String userId;
    private final long createdAt;
    private final long ttlMillis;

    private Status status = Status.PENDING;

    public MagicLinkToken(final String token, final String userId, final long createdAt, final long ttlMillis) {
        this.token = token;
        this.userId = userId;
        this.createdAt = createdAt;
        this.ttlMillis = ttlMillis;
    }

    public String token() {
        return token;
    }

    public String userId() {
        return userId;
    }

    public Status status() {
        return status;
    }

    public boolean isExpired(final long now) {
        return now - createdAt >= ttlMillis;
    }

    /** Single-use: returns the bound user id once for a PENDING, non-expired token, then null. */
    public String consume(final long now) {
        if (status != Status.PENDING) {
            return null;
        }
        if (isExpired(now)) {
            status = Status.EXPIRED;
            return null;
        }
        status = Status.USED;
        return userId;
    }
}
