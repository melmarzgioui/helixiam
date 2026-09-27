/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.e2e;

import io.helixiam.authorization.service.emailverification.EmailVerificationMessage;
import io.helixiam.authorization.service.emailverification.EmailVerificationSender;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Primary;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * Test-only (e2e context): records verification emails instead of sending them, per recipient. Enabled by the same
 * switch as {@link CapturingMagicLinkSender} (it captures every emailed link of the e2e server).
 */
@Component
@Primary
@ConditionalOnProperty(name = "helix.e2e.capture-magic-links", havingValue = "true")
public class CapturingEmailVerificationSender implements EmailVerificationSender {

    private static final Map<String, List<String>> SENT = new ConcurrentHashMap<>();

    @Override
    public boolean send(final EmailVerificationMessage message) {
        SENT.computeIfAbsent(message.email(), k -> new CopyOnWriteArrayList<>()).add(message.link());
        return true;
    }

    public static List<String> linksFor(final String email) {
        return SENT.getOrDefault(email, List.of());
    }
}
