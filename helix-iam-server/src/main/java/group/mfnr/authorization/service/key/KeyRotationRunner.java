package group.mfnr.authorization.service.key;

import group.mfnr.authorization.domain.realm.RealmKey;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

/**
 * Helix IAM E1.4: operational escape hatch to force a one-shot signing-key rotation at
 * startup. When the {@code HELIX_ROTATE_REALM} environment variable names a realm, the
 * realm's ACTIVE key is demoted to ROTATED (kept in the published JWKS for the verification
 * overlap) and a fresh ACTIVE key is generated — exercising {@link RealmKeyService#rotate}.
 *
 * <p>Unset by default (no-op). This is a stop-gap until the admin rotation endpoint lands;
 * it lets a forced rotation be performed without a code change and underpins live rotation
 * validation. Rotation is idempotent only in the sense that each restart-with-the-flag rotates
 * once, so the flag should be cleared after use.
 */
@Component
public class KeyRotationRunner implements ApplicationRunner {

    private static final Logger LOG = LogManager.getLogger(KeyRotationRunner.class);
    private static final String ROTATE_REALM_ENV = "HELIX_ROTATE_REALM";

    private final RealmKeyService realmKeyService;

    public KeyRotationRunner(final RealmKeyService realmKeyService) {
        this.realmKeyService = realmKeyService;
    }

    @Override
    public void run(final ApplicationArguments args) {
        final String realmId = System.getenv(ROTATE_REALM_ENV);
        if (!StringUtils.hasText(realmId)) {
            return;
        }
        try {
            final RealmKey rotated = realmKeyService.rotate(realmId.trim());
            LOG.warn("HELIX_ROTATE_REALM set: rotated signing key for realm '{}'; new ACTIVE kid={}",
                    realmId.trim(), rotated.getKeyId());
        } catch (final RuntimeException e) {
            LOG.error("Forced rotation for realm '{}' failed: {}", realmId.trim(), e.getMessage());
        }
    }
}
