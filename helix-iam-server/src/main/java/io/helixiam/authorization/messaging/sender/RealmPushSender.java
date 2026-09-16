package io.helixiam.authorization.messaging.sender;

import io.helixiam.authorization.amqp.messaging.DevicePushTokenDto;
import io.helixiam.authorization.amqp.messaging.MessagingAdminPublisher;
import io.helixiam.authorization.flow.push.PushMessage;
import io.helixiam.authorization.flow.push.PushSender;
import io.helixiam.authorization.messaging.MessageVariables;
import io.helixiam.authorization.messaging.MessagingService;
import io.helixiam.authorization.security.realm.RealmContextHolder;
import io.helixiam.authorization.service.UserInfoService;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Helix IAM notifications (N6c): the live push-approval sender. Looks up the user's registered device tokens,
 * renders the realm's {@code push-approval} template (with the number-matching digit + the user's claims), and
 * dispatches via the realm's configured FCM / APNs providers through {@link MessagingService}. The structured
 * {@code data} carries the approval id, challenge and number-matching choices the app acts on. Falls back to
 * logging when no push provider or device token is available — so the flow is always exercisable.
 */
public class RealmPushSender implements PushSender {

    private static final Logger LOG = LogManager.getLogger(RealmPushSender.class);

    private final MessagingService messaging;
    private final MessagingAdminPublisher publisher;
    private final UserInfoService userInfo;

    public RealmPushSender(final MessagingService messaging, final MessagingAdminPublisher publisher,
                           final UserInfoService userInfo) {
        this.messaging = messaging;
        this.publisher = publisher;
        this.userInfo = userInfo;
    }

    @Override
    public void send(final PushMessage message) {
        final String realm = RealmContextHolder.get() == null ? "master" : RealmContextHolder.get();
        try {
            final List<DevicePushTokenDto> tokens = publisher.listPushTokens(
                    new MessagingAdminPublisher.PushTokenQuery(realm, message.userId()));
            if (tokens != null && !tokens.isEmpty()) {
                final Map<String, String> base = new LinkedHashMap<>();
                base.put("realm", realm);
                base.put("number", String.valueOf(message.expectedNumber()));
                base.put("user", firstNonBlank(safeProfile(message.userId())));
                final Map<String, String> vars = MessageVariables.withUserClaims(base, safeProfile(message.userId()));
                final Map<String, String> data = new LinkedHashMap<>();
                data.put("approvalId", message.approvalId());
                data.put("challenge", message.challenge());
                data.put("expectedNumber", String.valueOf(message.expectedNumber()));
                data.put("candidates", message.candidates() == null ? "" : message.candidates().stream()
                        .map(String::valueOf).collect(Collectors.joining(",")));
                if (messaging.sendPush(realm, tokens, "push-approval", vars, data)) {
                    LOG.info("Push approval {} sent to user {} ({} device(s)) via realm {}",
                            message.approvalId(), message.userId(), tokens.size(), realm);
                    return;
                }
            }
        } catch (final RuntimeException e) {
            LOG.warn("Push approval send failed for user {} (logging as fallback): {}", message.userId(), e.getMessage());
        }
        LOG.info("[DEV PUSH] approval {} for user {} (no push provider/device): match number {}",
                message.approvalId(), message.userId(), message.expectedNumber());
    }

    private Map<String, String> safeProfile(final String userId) {
        try {
            final Map<String, String> p = userInfo.getOidcClaimProfile(userId);
            return p == null ? Map.of() : p;
        } catch (final RuntimeException e) {
            return Map.of();
        }
    }

    private static String firstNonBlank(final Map<String, String> profile) {
        for (final String key : new String[]{"name", "given_name", "email"}) {
            final String v = profile.get(key);
            if (v != null && !v.isBlank()) {
                return v;
            }
        }
        return "there";
    }
}
