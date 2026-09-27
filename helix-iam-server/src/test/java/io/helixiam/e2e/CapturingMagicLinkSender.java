/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.e2e;

import io.helixiam.authorization.service.magiclink.MagicLinkMessage;
import io.helixiam.authorization.service.magiclink.MagicLinkSender;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Primary;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;

/** Test-only (e2e context): records magic-link emails instead of sending them, per recipient. */
@Component
@Primary
@ConditionalOnProperty(name = "helix.e2e.capture-magic-links", havingValue = "true")
public class CapturingMagicLinkSender implements MagicLinkSender {

    private static final Map<String, List<String>> SENT = new ConcurrentHashMap<>();

    @Override
    public void send(final MagicLinkMessage message) {
        SENT.computeIfAbsent(message.email(), k -> new CopyOnWriteArrayList<>()).add(message.link());
    }

    public static List<String> linksFor(final String email) {
        return SENT.getOrDefault(email, List.of());
    }
}
