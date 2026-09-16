package group.mfnr.authorization.messaging.sender;

import group.mfnr.authorization.flow.authenticators.otp.OtpSender;
import group.mfnr.authorization.messaging.MessageVariables;
import group.mfnr.authorization.messaging.MessagingService;
import group.mfnr.authorization.security.realm.RealmContextHolder;
import group.mfnr.authorization.service.UserInfoService;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Helix IAM notifications (N3): the live SMS-OTP sender. Resolves the user's phone number + the in-flight
 * realm, renders the realm's {@code otp-sms} template, and dispatches through the configured SMS provider via
 * {@link MessagingService}. Falls back to logging the code (the dev behaviour) when the realm has no SMS
 * provider configured or the user has no phone number — so the flow is always exercisable.
 */
public class RealmSmsOtpSender implements OtpSender {

    private static final Logger LOG = LogManager.getLogger(RealmSmsOtpSender.class);

    private final MessagingService messaging;
    private final UserInfoService userInfo;

    public RealmSmsOtpSender(final MessagingService messaging, final UserInfoService userInfo) {
        this.messaging = messaging;
        this.userInfo = userInfo;
    }

    @Override
    public void send(final String userId, final String code) {
        final String realm = RealmContextHolder.get() == null ? "master" : RealmContextHolder.get();
        final Map<String, String> profile = safeProfile(userId);
        final String phone = firstNonBlank(profile.get("phoneNumber"), profile.get("phone_number"), profile.get("phone"));
        if (phone != null) {
            try {
                final Map<String, String> vars = vars(realm, code, profile);
                if (messaging.sendSms(realm, phone, "otp-sms", vars)) {
                    LOG.info("SMS OTP sent to user {} via realm {} provider", userId, realm);
                    return;
                }
            } catch (final RuntimeException e) {
                LOG.warn("SMS OTP send failed for user {} (logging code as fallback): {}", userId, e.getMessage());
            }
        }
        LOG.info("[DEV] SMS OTP for user {} (no SMS provider/phone): code = {}", userId, code);
    }

    private Map<String, String> safeProfile(final String userId) {
        try {
            final Map<String, String> p = userInfo.getOidcClaimProfile(userId);
            return p == null ? Map.of() : p;
        } catch (final RuntimeException e) {
            return Map.of();
        }
    }

    private static Map<String, String> vars(final String realm, final String code, final Map<String, String> profile) {
        final Map<String, String> base = new LinkedHashMap<>();
        base.put("realm", realm);
        base.put("code", code);
        base.put("ttl", "5 minutes");
        base.put("user", firstNonBlank(profile.get("name"), profile.get("given_name"), profile.get("email"), "there"));
        // Expose every user claim under user.<claim> ({{user.email}}, {{user.given_name}}, …).
        return MessageVariables.withUserClaims(base, profile);
    }

    private static String firstNonBlank(final String... values) {
        for (final String v : values) {
            if (v != null && !v.isBlank()) {
                return v;
            }
        }
        return null;
    }
}
