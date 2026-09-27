/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.e2e;

import io.helixiam.authorization.session.logout.BackchannelLogoutNotifier;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * Test-only (e2e context): records OIDC Back-Channel Logout POSTs ({@code logout_token}s) per back-channel URI
 * instead of sending them, so a test can validate each token as a relying party would.
 */
@Component
@ConditionalOnProperty(name = "helix.e2e.capture-backchannel-logout", havingValue = "true")
public class CapturingBackchannelPoster implements BackchannelLogoutNotifier.Poster {

    private static final Map<String, List<String>> SENT = new ConcurrentHashMap<>();

    @Override
    public void post(final String uri, final String logoutToken) {
        SENT.computeIfAbsent(uri, k -> new CopyOnWriteArrayList<>()).add(logoutToken);
    }

    /** Every logout_token POSTed to {@code uri}, oldest first. */
    public static List<String> tokensFor(final String uri) {
        return SENT.getOrDefault(uri, List.of());
    }
}
