package io.helixiam.authorization.service.mfa;

import io.helixiam.authorization.domain.mfa.HotpCredentialEntity;
import io.helixiam.authorization.repository.mfa.HotpCredentialRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.SecureRandom;
import java.util.Base64;

/**
 * Helix IAM E3.4: verifies HOTP codes against a user's stored secret + counter, advancing the
 * counter on success and accepting a code within a small look-ahead window (resync after a few
 * skipped presses). Enrollment generates and stores the secret.
 */
@Service
public class HotpService {

    private static final int DIGITS = 6;
    private static final int LOOK_AHEAD = 5;
    private static final SecureRandom RANDOM = new SecureRandom();

    private final HotpCredentialRepository repository;

    public HotpService(final HotpCredentialRepository repository) {
        this.repository = repository;
    }

    /** Verifies a code; on success advances the stored counter past the matched value. */
    @Transactional
    public boolean verify(final String userId, final String code) {
        return repository.findByUserId(userId).map(credential -> {
            final byte[] secret = Base64.getDecoder().decode(credential.getSecret());
            for (int offset = 0; offset <= LOOK_AHEAD; offset++) {
                final long counter = credential.getCounter() + offset;
                if (Hotp.generate(secret, counter, DIGITS).equals(code)) {
                    credential.setCounter(counter + 1);
                    repository.save(credential);
                    return true;
                }
            }
            return false;
        }).orElse(false);
    }

    /** Enrolls a fresh HOTP secret for the user (Base64), resetting the counter. */
    @Transactional
    public String enroll(final String userId) {
        final byte[] secret = new byte[20];
        RANDOM.nextBytes(secret);
        final String encoded = Base64.getEncoder().encodeToString(secret);
        repository.save(new HotpCredentialEntity(userId, encoded, 0));
        return encoded;
    }
}
