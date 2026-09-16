package io.helixiam.authorization.security.flow;

import io.helixiam.authorization.flow.authenticators.otp.OtpSender;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.stereotype.Component;

/**
 * Helix IAM E3.1: default {@link OtpSender} that logs the code rather than dispatching it — the
 * safe no-gateway default for dev/e2e. Production replaces this bean with an SMS-gateway / email
 * adapter (the notification starter). Never log codes in production.
 */
@Component
public class LoggingOtpSender implements OtpSender {

    private static final Logger LOG = LogManager.getLogger(LoggingOtpSender.class);

    @Override
    public void send(final String userId, final String code) {
        LOG.info("[DEV] One-time code for user {}: {}", userId, code);
    }
}
