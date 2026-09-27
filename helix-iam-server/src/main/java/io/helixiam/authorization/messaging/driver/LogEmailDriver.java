/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.messaging.driver;

import io.helixiam.authorization.amqp.messaging.ResolvedProviderDto;
import io.helixiam.authorization.messaging.email.DeliveryResult;
import io.helixiam.authorization.messaging.email.EmailMessage;
import io.helixiam.authorization.messaging.email.EmailTransport;
import io.helixiam.common.log.LogSafe;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.stereotype.Component;

/**
 * The {@code LOG} email driver: nothing is sent; one line is logged per email with its message id and subject. The
 * body (which holds links and codes) and the recipient are never logged. For development and for realms that must
 * not send email.
 */
@Component
public class LogEmailDriver implements EmailTransport {

    public static final String DRIVER = "LOG";
    private static final Logger LOG = LogManager.getLogger(LogEmailDriver.class);

    @Override
    public String driver() {
        return DRIVER;
    }

    @Override
    public DeliveryResult deliver(final ResolvedProviderDto provider, final EmailMessage message) {
        LOG.info("LOG email driver: not sending email {} (subject \"{}\", {} recipient(s))",
                LogSafe.sanitize(message.messageId()), LogSafe.sanitize(message.subject()), message.to().size());
        return DeliveryResult.accepted(message.messageId(), "Logged, not sent (LOG driver)");
    }
}
