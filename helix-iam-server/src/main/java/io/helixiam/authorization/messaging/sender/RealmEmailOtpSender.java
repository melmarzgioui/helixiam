package io.helixiam.authorization.messaging.sender;

import io.helixiam.authorization.flow.authenticators.otp.OtpSender;
import io.helixiam.authorization.messaging.MessagingService;
import io.helixiam.authorization.security.realm.RealmContextHolder;
import io.helixiam.authorization.service.UserInfoService;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Helix IAM notifications (N3): the live Email-OTP sender. Resolves the user's email + the in-flight realm,
 * renders the realm's {@code otp-email} template (subject + body), and dispatches through the configured email
 * provider via {@link MessagingService}. Falls back to logging the code when no email provider is configured
 * or the user has no email — so the flow is always exercisable.
 */
public class RealmEmailOtpSender implements OtpSender {

    private static final Logger LOG = LogManager.getLogger(RealmEmailOtpSender.class);

    private final MessagingService messaging;
    private final UserInfoService userInfo;

    public RealmEmailOtpSender(final MessagingService messaging, final UserInfoService userInfo) {
        this.messaging = messaging;
        this.userInfo = userInfo;
    }

    @Override
    public void send(final String userId, final String code) {
        final String realm = RealmContextHolder.get() == null ? "master" : RealmContextHolder.get();
        final Map<String, String> profile = safeProfile(userId);
        final String email = profile.get("email");
        if (email != null && !email.isBlank()) {
            try {
                final Map<String, String> base = new LinkedHashMap<>();
                base.put("realm", realm);
                base.put("code", code);
                base.put("ttl", "5 minutes");
                base.put("user", firstNonBlank(profile.get("name"), profile.get("given_name"), email, "there"));
                // Expose every user claim under user.<claim> ({{user.email}}, {{user.given_name}}, …).
                final Map<String, String> vars = io.helixiam.authorization.messaging.MessageVariables.withUserClaims(base, profile);
                if (messaging.sendEmail(realm, email, "otp-email", vars)) {
                    LOG.info("Email OTP sent to user {} via realm {} provider", userId, realm);
                    return;
                }
            } catch (final RuntimeException e) {
                LOG.warn("Email OTP send failed for user {} (logging code as fallback): {}", userId, e.getMessage());
            }
        }
        LOG.info("[DEV] Email OTP for user {} (no email provider/address): code = {}", userId, code);
    }

    private Map<String, String> safeProfile(final String userId) {
        try {
            final Map<String, String> p = userInfo.getOidcClaimProfile(userId);
            return p == null ? Map.of() : p;
        } catch (final RuntimeException e) {
            return Map.of();
        }
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
