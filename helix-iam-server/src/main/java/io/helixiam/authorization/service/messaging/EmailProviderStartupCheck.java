/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.service.messaging;

import io.helixiam.common.log.LogSafe;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;

/**
 * At startup, repairs realms saved before the one-active-email-provider rule
 * ({@link MessagingAdminService#enforceSingleEnabledEmailProvider()}). Never fails the startup.
 */
@Component
public class EmailProviderStartupCheck {

    private static final Logger LOG = LogManager.getLogger(EmailProviderStartupCheck.class);

    private final MessagingAdminService service;

    public EmailProviderStartupCheck(final MessagingAdminService service) {
        this.service = service;
    }

    @EventListener(ApplicationReadyEvent.class)
    public void enforce() {
        try {
            service.enforceSingleEnabledEmailProvider();
        } catch (final RuntimeException e) {
            LOG.warn("Could not check the realms' email providers: {}", LogSafe.sanitize(e.getClass().getSimpleName()));
        }
    }
}
