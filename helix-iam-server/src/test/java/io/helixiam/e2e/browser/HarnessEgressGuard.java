/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.e2e.browser;

import io.helixiam.common.net.OutboundUrlGuard;
import io.helixiam.common.net.SsrfBlockedException;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Primary;
import org.springframework.stereotype.Component;

import java.net.URI;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Test-only (e2e context): the production SSRF guard, plus one narrow exception for the harness's own loopback
 * servers. The test relying party ({@link TestRelyingParty}, back-channel logout) and the mail sink
 * ({@link MailSink}, the realm's HTTP email driver) listen on {@code 127.0.0.1:<random port>}, which the real guard
 * refuses as loopback (the email API mocks of the email-delivery tests listen on https). Only
 * {@code http(s)://127.0.0.1:<registered port>} is let through; every other URL, including
 * the IdP's own port and any other loopback port, still gets the full block-private check (so
 * {@code SamlMetadataImportE2eTest} keeps proving the guard).
 */
@Component
@Primary
@ConditionalOnProperty(name = "helix.e2e.harness-egress", havingValue = "true")
public class HarnessEgressGuard extends OutboundUrlGuard {

    private static final Set<Integer> HARNESS_PORTS = ConcurrentHashMap.newKeySet();

    public HarnessEgressGuard() {
        super(false);
    }

    /** Lets the server call {@code http://127.0.0.1:port/…} (a harness-owned listener). */
    static void allow(final int port) {
        HARNESS_PORTS.add(port);
    }

    static void revoke(final int port) {
        HARNESS_PORTS.remove(port);
    }

    @Override
    public void checkAllowed(final String url) throws SsrfBlockedException {
        if (isHarnessUrl(url)) {
            return;
        }
        super.checkAllowed(url);
    }

    /** The same exception for callers on the pinned transport, which ask for the validated address. */
    @Override
    public ResolvedTarget resolveAllowed(final String url) throws SsrfBlockedException {
        if (isHarnessUrl(url)) {
            final URI uri = URI.create(url.trim());
            try {
                return new ResolvedTarget(uri, uri.getHost(), uri.getPort(),
                        java.util.List.of(java.net.InetAddress.getByAddress(new byte[] {127, 0, 0, 1})));
            } catch (final java.net.UnknownHostException e) {
                throw new IllegalStateException(e);
            }
        }
        return super.resolveAllowed(url);
    }

    private static boolean isHarnessUrl(final String url) {
        if (url == null) {
            return false;
        }
        try {
            final URI uri = new URI(url.trim());
            return ("http".equalsIgnoreCase(uri.getScheme()) || "https".equalsIgnoreCase(uri.getScheme()))
                    && "127.0.0.1".equals(uri.getHost())
                    && HARNESS_PORTS.contains(uri.getPort());
        } catch (final java.net.URISyntaxException e) {
            return false;
        }
    }
}
