package io.helixiam.authorization.flow.push;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Helix IAM E4.3: dev default {@link PushSender} — logs the approval instead of calling FCM/APNs, so
 * the push flow is exercisable without push credentials. Real FCM/APNs adapters replace it
 * ({@code @ConditionalOnMissingBean}). The expected number is logged so a developer can complete the
 * number-matching approval locally.
 */
public class LoggingPushSender implements PushSender {

    private static final Logger LOG = LogManager.getLogger(LoggingPushSender.class);

    @Override
    public void send(final PushMessage message) {
        LOG.info("[DEV PUSH] approval {} for user {}: match number {} (choices {}) — challenge {}",
                message.approvalId(), message.userId(), message.expectedNumber(),
                message.candidates(), message.challenge());
    }
}
