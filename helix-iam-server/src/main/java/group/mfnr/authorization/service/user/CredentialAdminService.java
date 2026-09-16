package group.mfnr.authorization.service.user;

import group.mfnr.authorization.domain.device.DeviceCredentialEntity;
import group.mfnr.authorization.domain.mfa.HotpCredentialEntity;
import group.mfnr.authorization.domain.mfa.WebAuthnCredentialEntity;
import group.mfnr.authorization.domain.user.UserCredentials;
import group.mfnr.authorization.domain.user.admin.CredentialSummary;
import group.mfnr.authorization.repository.UserCredentialsRepository;
import group.mfnr.authorization.repository.device.DeviceCredentialRepository;
import group.mfnr.authorization.repository.mfa.HotpCredentialRepository;
import group.mfnr.authorization.repository.mfa.RecoveryCodeRepository;
import group.mfnr.authorization.repository.mfa.WebAuthnCredentialRepository;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

/**
 * Helix IAM E8.5: read + revoke a realm user's enrolled authentication factors for the console's
 * "Device &amp; passkeys" screen. It aggregates across every factor store the platform already keeps —
 * WebAuthn passkeys, VeridPay-style device keys, the TOTP secret on the user record, HOTP, and active
 * recovery codes — into a flat, secret-free {@link CredentialSummary} list, and revokes one factor by
 * (type, id), each delete scoped to the store that owns that type and guarded by ownership.
 */
@Service
public class CredentialAdminService {

    private static final Logger LOG = LogManager.getLogger(CredentialAdminService.class);

    /** Fixed ids for the singleton factors (one per user), so the console has a stable revoke handle. */
    private static final String TOTP_ID = "totp";
    private static final String HOTP_ID = "hotp";
    private static final String RECOVERY_ID = "recovery-codes";

    private final DeviceCredentialRepository devices;
    private final WebAuthnCredentialRepository passkeys;
    private final HotpCredentialRepository hotp;
    private final RecoveryCodeRepository recovery;
    private final UserCredentialsRepository users;

    public CredentialAdminService(final DeviceCredentialRepository devices,
                                  final WebAuthnCredentialRepository passkeys,
                                  final HotpCredentialRepository hotp,
                                  final RecoveryCodeRepository recovery,
                                  final UserCredentialsRepository users) {
        this.devices = devices;
        this.passkeys = passkeys;
        this.hotp = hotp;
        this.recovery = recovery;
        this.users = users;
    }

    /** Every enrolled factor for the user, newest-store-first; empty when the user has none. */
    public List<CredentialSummary> list(final String userId) {
        final List<CredentialSummary> out = new ArrayList<>();

        for (final WebAuthnCredentialEntity p : passkeys.findAllByUserId(userId)) {
            out.add(new CredentialSummary("passkey", p.getCredentialId(), "Passkey (FIDO2)",
                    "Sign-count " + p.getSignCount(), millis(p.getCreationDate()), null, true));
        }
        for (final DeviceCredentialEntity d : devices.findAllByUserId(userId)) {
            out.add(new CredentialSummary("device", d.getDeviceId(), "Trusted device",
                    deviceDetail(d), millis(d.getCreationDate()), millis(d.getLastUsedDate()), true));
        }
        users.findByUserId(userId).ifPresent(user -> {
            if (user.getMfaSecret() != null && !user.getMfaSecret().isBlank()) {
                out.add(new CredentialSummary("totp", TOTP_ID, "Authenticator app (TOTP)",
                        "Time-based one-time passwords", null, null, true));
            }
        });
        hotp.findByUserId(userId).ifPresent(h -> out.add(new CredentialSummary("hotp", HOTP_ID,
                "Authenticator app (HOTP)", "Counter " + h.getCounter(), null, null, true)));
        final int activeCodes = recovery.findAllByUserIdAndUsedFalse(userId).size();
        if (activeCodes > 0) {
            out.add(new CredentialSummary("recovery-code", RECOVERY_ID, "Recovery codes",
                    activeCodes + " code" + (activeCodes == 1 ? "" : "s") + " remaining", null, null, true));
        }
        return out;
    }

    /** Revoke one factor by (type, id); {@code false} if it is absent or not owned by the user. */
    @Transactional
    public boolean revoke(final String userId, final String type, final String id) {
        return switch (type) {
            case "passkey" -> passkeys.findById(id)
                    .filter(p -> userId.equals(p.getUserId()))
                    .map(p -> {
                        passkeys.deleteById(id);
                        LOG.debug("Revoked passkey {} for user {}", id, userId);
                        return true;
                    }).orElse(false);
            case "device" -> devices.findById(id)
                    .filter(d -> userId.equals(d.getUserId()))
                    .map(d -> {
                        devices.deleteById(id);
                        LOG.debug("Revoked device {} for user {}", id, userId);
                        return true;
                    }).orElse(false);
            case "totp" -> users.findByUserId(userId)
                    .filter(u -> u.getMfaSecret() != null && !u.getMfaSecret().isBlank())
                    .map(u -> {
                        u.setMfaSecret(null);
                        u.setMfaEnabled(false);
                        users.save(u);
                        LOG.debug("Revoked TOTP for user {}", userId);
                        return true;
                    }).orElse(false);
            case "hotp" -> hotp.findByUserId(userId)
                    .map(h -> {
                        hotp.deleteById(userId);
                        LOG.debug("Revoked HOTP for user {}", userId);
                        return true;
                    }).orElse(false);
            case "recovery-code" -> {
                if (recovery.findAllByUserIdAndUsedFalse(userId).isEmpty()) {
                    yield false;
                }
                recovery.deleteAllByUserId(userId);
                LOG.debug("Revoked recovery codes for user {}", userId);
                yield true;
            }
            default -> false;
        };
    }

    private static String deviceDetail(final DeviceCredentialEntity d) {
        final String platform = d.getPlatform() == null || d.getPlatform().isBlank() ? "unattested" : d.getPlatform();
        return d.isBiometric() ? platform + " · biometric-gated" : platform;
    }

    private static Long millis(final Date date) {
        return date == null ? null : date.getTime();
    }
}
