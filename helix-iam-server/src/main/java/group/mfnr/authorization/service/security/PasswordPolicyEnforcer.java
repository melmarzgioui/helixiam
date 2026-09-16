package group.mfnr.authorization.service.security;

import group.mfnr.authorization.domain.realm.RealmConfig;
import group.mfnr.authorization.domain.security.PasswordHistory;
import group.mfnr.authorization.repository.security.PasswordHistoryRepository;
import group.mfnr.authorization.service.PasswordEncoderService;
import group.mfnr.authorization.service.RealmService;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

/**
 * Auth-hardening (features 3 + 4): the single enforcement point for setting a password. Combines the pure
 * {@link PasswordPolicy} (length/character-class/not-username), reuse history ({@code historyCount}) and the
 * breached-password (HIBP) check, all gated by the realm's configuration. Throws
 * {@link PasswordPolicyException} when the candidate is rejected so callers can surface a clear message.
 *
 * <p>Use {@link #enforce} before encoding+saving a new password, then {@link #recordHistory} with the
 * resulting hash so future changes can detect reuse.
 */
@Service
public class PasswordPolicyEnforcer {

    private static final Logger LOG = LogManager.getLogger(PasswordPolicyEnforcer.class);

    private final RealmService realmService;
    private final PasswordEncoderService passwordEncoderService;
    private final PasswordHistoryRepository passwordHistoryRepository;
    private final BreachedPasswordChecker breachedPasswordChecker;

    @Autowired
    public PasswordPolicyEnforcer(final RealmService realmService,
                                  final PasswordEncoderService passwordEncoderService,
                                  final PasswordHistoryRepository passwordHistoryRepository,
                                  final BreachedPasswordChecker breachedPasswordChecker) {
        this.realmService = realmService;
        this.passwordEncoderService = passwordEncoderService;
        this.passwordHistoryRepository = passwordHistoryRepository;
        this.breachedPasswordChecker = breachedPasswordChecker;
    }

    /** Raised when a candidate password violates the realm's policy. */
    public static class PasswordPolicyException extends RuntimeException {
        public PasswordPolicyException(final String message) {
            super(message);
        }
    }

    /**
     * Validates a candidate raw password against the realm's policy. Throws {@link PasswordPolicyException}
     * on the first failure (length/character class/not-username, then reuse history, then HIBP).
     *
     * @param realmId  the realm whose policy applies ({@code null} → platform defaults)
     * @param userId   the user (for history lookup); may be {@code null} on create
     * @param username the username (for the not-username rule); may be {@code null}
     * @param rawPassword the candidate password
     */
    public void enforce(final String realmId, final String userId, final String username, final String rawPassword) {
        final RealmConfig realm = realmService.getOrDefault(realmId);

        final List<String> violations = PasswordPolicy.fromRealm(realm).validate(rawPassword, username);
        if (!violations.isEmpty()) {
            throw new PasswordPolicyException(violations.get(0));
        }

        if (realm.getPasswordHistoryCount() > 0 && userId != null) {
            final List<PasswordHistory> recent = passwordHistoryRepository
                    .findByUserIdOrderByCreationDateDesc(userId).stream()
                    .limit(realm.getPasswordHistoryCount())
                    .toList();
            for (final PasswordHistory prior : recent) {
                if (passwordEncoderService.matches(rawPassword, prior.getPasswordHash(), null)) {
                    throw new PasswordPolicyException("Password must not match one of your last "
                            + realm.getPasswordHistoryCount() + " passwords.");
                }
            }
        }

        if (realm.isBreachedPasswordCheck() && breachedPasswordChecker.isBreached(rawPassword)) {
            throw new PasswordPolicyException("This password has appeared in a known data breach. Choose another.");
        }
    }

    /** Records the just-set password hash in history (and prunes beyond the realm's window). */
    public void recordHistory(final String realmId, final String userId, final String passwordHash) {
        if (userId == null || passwordHash == null) {
            return;
        }
        final int count = realmService.getOrDefault(realmId).getPasswordHistoryCount();
        if (count <= 0) {
            return;
        }
        passwordHistoryRepository.save(new PasswordHistory(userId, passwordHash));
        final List<PasswordHistory> all = passwordHistoryRepository.findByUserIdOrderByCreationDateDesc(userId);
        if (all.size() > count) {
            passwordHistoryRepository.deleteAll(all.subList(count, all.size()));
        }
        LOG.debug("Recorded password history for user {} in realm {}", userId, realmId);
    }
}
