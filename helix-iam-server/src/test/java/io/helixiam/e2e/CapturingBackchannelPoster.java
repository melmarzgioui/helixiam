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
 * Test-only (e2e context): records OIDC Back-Channel Logout POSTs ({@code logout_token}s) per back-channel URI,
 * so a test can validate each token as a relying party would. A URI on the loopback interface (the browser
 * harness's {@code TestRelyingParty}) also receives the real form POST, as a relying party would; other URIs
 * (placeholders such as {@code https://rp.example/...}) are recorded only.
 */
@Component
@ConditionalOnProperty(name = "helix.e2e.capture-backchannel-logout", havingValue = "true")
public class CapturingBackchannelPoster implements BackchannelLogoutNotifier.Poster {

    private static final Map<String, List<String>> SENT = new ConcurrentHashMap<>();

    @Override
    public void post(final String uri, final String logoutToken) {
        SENT.computeIfAbsent(uri, k -> new CopyOnWriteArrayList<>()).add(logoutToken);
        final java.net.URI target = java.net.URI.create(uri);
        if ("127.0.0.1".equals(target.getHost()) || "localhost".equals(target.getHost())) {
            try {
                HTTP.send(java.net.http.HttpRequest.newBuilder(target)
                                .header("Content-Type", "application/x-www-form-urlencoded")
                                .POST(java.net.http.HttpRequest.BodyPublishers.ofString("logout_token="
                                        + java.net.URLEncoder.encode(logoutToken, java.nio.charset.StandardCharsets.UTF_8)))
                                .build(),
                        java.net.http.HttpResponse.BodyHandlers.discarding());
            } catch (final java.io.IOException | InterruptedException e) {
                // Best effort, like the production poster: a relying party that is down does not fail logout.
            }
        }
    }

    private static final java.net.http.HttpClient HTTP = java.net.http.HttpClient.newBuilder()
            .connectTimeout(java.time.Duration.ofSeconds(5)).build();

    /** Every logout_token POSTed to {@code uri}, oldest first. */
    public static List<String> tokensFor(final String uri) {
        return SENT.getOrDefault(uri, List.of());
    }
}
