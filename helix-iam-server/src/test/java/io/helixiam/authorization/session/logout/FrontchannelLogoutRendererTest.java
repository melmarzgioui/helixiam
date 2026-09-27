/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.session.logout;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Helix IAM SSO P6: the OIDC Front-Channel Logout interstitial loads one iframe per client, each pointed at its
 * {@code frontchannel_logout_uri} carrying {@code iss}+{@code sid}. (The page itself is the themed template
 * {@code logout/frontchannel}, escaped by Thymeleaf; see {@code ThemedTemplatesTest} and the browser test.)
 */
class FrontchannelLogoutRendererTest {

    @Test
    void oneFramePerClient_withIssAndSid_keepingAnExistingQuery() {
        final List<String> frames = FrontchannelLogoutRenderer.frameUrls("https://idp/realms/master", "sid-1", List.of(
                new LogoutTargetResolver.FrontchannelTarget("a", "https://a/fc"),
                new LogoutTargetResolver.FrontchannelTarget("b", "https://b/fc?x=1"),
                new LogoutTargetResolver.FrontchannelTarget("c", " ")));

        assertThat(frames).containsExactly("https://a/fc?iss=https%3A%2F%2Fidp%2Frealms%2Fmaster&sid=sid-1",
                "https://b/fc?x=1&iss=https%3A%2F%2Fidp%2Frealms%2Fmaster&sid=sid-1");
    }

    @Test
    void withoutAnIssuer_onlyTheSid() {
        assertThat(FrontchannelLogoutRenderer.frameUrls(null, "s 1", List.of(
                new LogoutTargetResolver.FrontchannelTarget("a", "https://a/fc")))).containsExactly("https://a/fc?sid=s+1");
    }
}
