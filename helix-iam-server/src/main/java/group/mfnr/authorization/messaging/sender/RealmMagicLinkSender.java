package group.mfnr.authorization.messaging.sender;

import group.mfnr.authorization.flow.magiclink.MagicLinkMessage;
import group.mfnr.authorization.flow.magiclink.MagicLinkSender;
import group.mfnr.authorization.messaging.MessageVariables;
import group.mfnr.authorization.messaging.MessagingService;
import group.mfnr.authorization.security.realm.RealmContextHolder;
import group.mfnr.authorization.service.UserInfoService;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Helix IAM notifications (N6b): the live passwordless magic-link sender. Resolves the in-flight realm + the
 * user's claims, renders the realm's {@code magic-link-email} template ({@code {{link}}}, {@code {{ttl}}},
 * {@code {{user}}} + every {@code {{user.<claim>}}}), and dispatches through the realm's configured email
 * provider via {@link MessagingService}. Falls back to logging the link (the dev behaviour) when the realm has
 * no email provider configured — so passwordless login is always exercisable.
 */
public class RealmMagicLinkSender implements MagicLinkSender {

    private static final Logger LOG = LogManager.getLogger(RealmMagicLinkSender.class);

    private final MessagingService messaging;
    private final UserInfoService userInfo;
    private final long ttlMillis;

    public RealmMagicLinkSender(final MessagingService messaging, final UserInfoService userInfo, final long ttlMillis) {
        this.messaging = messaging;
        this.userInfo = userInfo;
        this.ttlMillis = ttlMillis;
    }

    @Override
    public void send(final MagicLinkMessage message) {
        final String realm = RealmContextHolder.get() == null ? "master" : RealmContextHolder.get();
        final Map<String, String> profile = safeProfile(message.userId());
        try {
            final Map<String, String> base = new LinkedHashMap<>();
            base.put("realm", realm);
            base.put("link", message.link());
            base.put("ttl", humanTtl(ttlMillis));
            base.put("user", firstNonBlank(profile.get("name"), profile.get("given_name"), message.email(), "there"));
            final Map<String, String> vars = MessageVariables.withUserClaims(base, profile);
            if (messaging.sendEmail(realm, message.email(), "magic-link-email", vars)) {
                LOG.info("Magic link emailed to user {} via realm {} provider", message.userId(), realm);
                return;
            }
        } catch (final RuntimeException e) {
            LOG.warn("Magic-link send failed for user {} (logging link as fallback): {}", message.userId(), e.getMessage());
        }
        LOG.info("[DEV MAGIC-LINK] for user {} <{}> (no email provider): {}",
                message.userId(), message.email(), message.link());
    }

    private Map<String, String> safeProfile(final String userId) {
        try {
            final Map<String, String> p = userInfo.getOidcClaimProfile(userId);
            return p == null ? Map.of() : p;
        } catch (final RuntimeException e) {
            return Map.of();
        }
    }

    /** A friendly TTL like {@code "10 minutes"} from the configured millis. */
    private static String humanTtl(final long millis) {
        final long minutes = Math.max(1, millis / 60_000);
        return minutes + (minutes == 1 ? " minute" : " minutes");
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
