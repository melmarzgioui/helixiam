/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.session.logout;

import io.helixiam.authorization.security.PageCspPolicy;
import io.helixiam.authorization.theme.render.ThemedPageRenderer;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.stereotype.Component;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Helix IAM SSO P6: the OIDC Front-Channel Logout interstitial. The browser loads one hidden iframe per participating
 * client (each pointed at its {@code frontchannel_logout_uri} with the {@code iss}+{@code sid} query params per the
 * spec, so the RP can clear its own session), then moves on to the post-logout URI.
 *
 * <p>Item 6: the page is the themed template {@value #TEMPLATE} (the realm's theme, the user's language), with no
 * inline style or script: the iframes are {@code hidden} and the page moves on with a meta refresh (or its Continue
 * link). Its {@code frame-src} allows exactly the origins of those logout URLs ({@link PageCspPolicy#withFrames}); the
 * pages' default {@code frame-src 'none'} blocked them.
 */
@Component
public class FrontchannelLogoutRenderer {

    /** The template rendered. */
    public static final String TEMPLATE = "logout/frontchannel";

    private final ObjectProvider<ThemedPageRenderer> pages;
    private final ObjectProvider<PageCspPolicy> csp;

    public FrontchannelLogoutRenderer(final ObjectProvider<ThemedPageRenderer> pages,
                                      final ObjectProvider<PageCspPolicy> csp) {
        this.pages = pages;
        this.csp = csp;
    }

    /** Renders the interstitial as the response. */
    public void render(final HttpServletRequest request, final HttpServletResponse response, final String issuer,
                       final String sid, final List<LogoutTargetResolver.FrontchannelTarget> targets,
                       final String postLogoutRedirectUri) throws Exception {
        final String redirect = postLogoutRedirectUri == null || postLogoutRedirectUri.isBlank()
                ? "/" : postLogoutRedirectUri;
        final List<String> frames = frameUrls(issuer, sid, targets);
        final PageCspPolicy policy = csp.getIfAvailable();
        if (policy != null) {
            response.setHeader("Content-Security-Policy", policy.withFrames(request, frames));
        }
        pages.getObject().render(TEMPLATE, Map.of("frames", frames, "redirect", redirect), HttpServletResponse.SC_OK,
                request, response);
    }

    /** The iframe URLs: each client's front-channel logout URI with {@code iss} and {@code sid}. */
    static List<String> frameUrls(final String issuer, final String sid,
                                  final List<LogoutTargetResolver.FrontchannelTarget> targets) {
        final List<String> frames = new ArrayList<>();
        if (targets != null) {
            for (final LogoutTargetResolver.FrontchannelTarget target : targets) {
                if (target.frontchannelLogoutUri() != null && !target.frontchannelLogoutUri().isBlank()) {
                    frames.add(withIssSid(target.frontchannelLogoutUri(), issuer, sid));
                }
            }
        }
        return frames;
    }

    /** Append the OIDC {@code iss}+{@code sid} query params (preserving any existing query string). */
    private static String withIssSid(final String uri, final String issuer, final String sid) {
        final String sep = uri.contains("?") ? "&" : "?";
        final StringBuilder out = new StringBuilder(uri);
        if (issuer != null) {
            out.append(sep).append("iss=").append(URLEncoder.encode(issuer, StandardCharsets.UTF_8));
            if (sid != null && !sid.isBlank()) {
                out.append("&sid=").append(URLEncoder.encode(sid, StandardCharsets.UTF_8));
            }
        } else if (sid != null && !sid.isBlank()) {
            out.append(sep).append("sid=").append(URLEncoder.encode(sid, StandardCharsets.UTF_8));
        }
        return out.toString();
    }
}
