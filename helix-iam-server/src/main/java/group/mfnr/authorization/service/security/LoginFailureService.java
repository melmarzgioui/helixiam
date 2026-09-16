package group.mfnr.authorization.service.security;

import group.mfnr.authorization.domain.realm.RealmConfig;
import group.mfnr.authorization.domain.security.LoginFailure;
import group.mfnr.authorization.repository.security.LoginFailureRepository;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.function.Supplier;

/**
 * Auth-hardening (feature 1): the account-lockout / brute-force state machine.
 *
 * <p>Tracks failed password attempts per realm+user in {@link LoginFailure}. On each failure within the
 * realm's sliding {@code failureResetSeconds} window the counter increments; a failure that lands after the
 * window has elapsed restarts the count at 1. When the count reaches {@code maxLoginFailures} the account is
 * locked — either for {@code lockoutDurationSeconds} (temporary) or indefinitely ({@code permanentLockout}).
 * A successful login clears the row. The clock is injectable so the state machine is unit-testable.
 */
@Service
public class LoginFailureService {

    private static final Logger LOG = LogManager.getLogger(LoginFailureService.class);

    private final LoginFailureRepository repository;
    private final Supplier<Instant> clock;

    @Autowired
    public LoginFailureService(final LoginFailureRepository repository) {
        this(repository, Instant::now);
    }

    /** Test seam: inject the clock. */
    public LoginFailureService(final LoginFailureRepository repository, final Supplier<Instant> clock) {
        this.repository = repository;
        this.clock = clock;
    }

    /**
     * Whether the account is currently locked out (a {@code lockedUntil} in the future, or a permanent lock
     * encoded as {@link Instant#MAX}). Lockout is disabled when the realm has it turned off.
     */
    @Transactional(readOnly = true)
    public boolean isLockedOut(final RealmConfig realm, final String userId) {
        if (!realm.isLockoutEnabled() || userId == null) {
            return false;
        }
        return repository.findByRealmIdAndUserId(realm.getRealmId(), userId)
                .map(f -> isLocked(f, clock.get()))
                .orElse(false);
    }

    /** Pure predicate: is this counter row locked as of {@code now}? */
    public static boolean isLocked(final LoginFailure failure, final Instant now) {
        return failure.getLockedUntil() != null && failure.getLockedUntil().isAfter(now);
    }

    /**
     * Records a failed password attempt and applies the lockout policy. Returns {@code true} if the account
     * is now locked. No-op (returns {@code false}) when lockout is disabled for the realm.
     */
    @Transactional
    public boolean recordFailure(final RealmConfig realm, final String userId) {
        if (!realm.isLockoutEnabled() || userId == null) {
            return false;
        }
        final Instant now = clock.get();
        final LoginFailure failure = repository.findByRealmIdAndUserId(realm.getRealmId(), userId)
                .orElseGet(() -> new LoginFailure(realm.getRealmId(), userId));
        applyFailure(failure, realm, now);
        repository.save(failure);
        final boolean locked = isLocked(failure, now);
        if (locked) {
            LOG.info("Account {} in realm {} locked out after {} failures", userId, realm.getRealmId(),
                    failure.getFailureCount());
        }
        return locked;
    }

    /**
     * Pure state transition for a single failure (visible for testing). Increments within the sliding
     * window (or restarts it), then locks when the threshold is reached.
     */
    public static void applyFailure(final LoginFailure failure, final RealmConfig realm, final Instant now) {
        final int windowSeconds = Math.max(0, realm.getFailureResetSeconds());
        final boolean withinWindow = failure.getLastFailure() != null
                && !failure.getLastFailure().plusSeconds(windowSeconds).isBefore(now);
        final int next = withinWindow ? failure.getFailureCount() + 1 : 1;
        failure.setFailureCount(next);
        failure.setLastFailure(now);
        if (next >= Math.max(1, realm.getMaxLoginFailures())) {
            failure.setLockedUntil(realm.isPermanentLockout()
                    ? Instant.MAX
                    : now.plusSeconds(Math.max(1, realm.getLockoutDurationSeconds())));
        }
    }

    /** Clears the counter after a successful login. */
    @Transactional
    public void recordSuccess(final RealmConfig realm, final String userId) {
        if (userId == null) {
            return;
        }
        repository.findByRealmIdAndUserId(realm.getRealmId(), userId).ifPresent(repository::delete);
    }
}
