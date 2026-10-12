/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.wallet.web;

import io.helixiam.authorization.federation.IdentityProviderRegistry;
import io.helixiam.authorization.federation.wallet.WalletIdentityProvider;
import jakarta.servlet.http.HttpServletRequest;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Task 18 fix round 1: which requests start a wallet login, for the {@code wallet-start} rate limit: a
 * {@code GET /broker/<alias>} (after the realm routing stripped {@code /realms/<realm>}) whose alias is an EUDI wallet
 * provider. Other providers' starts and every other broker path are not counted.
 */
public final class WalletStartRequests {

    private static final Pattern START = Pattern.compile("^/broker/([^/]+)$");

    private WalletStartRequests() {
    }

    public static boolean isWalletStart(final HttpServletRequest request, final IdentityProviderRegistry registry) {
        if (registry == null || !"GET".equalsIgnoreCase(request.getMethod()) || request.getServletPath() == null) {
            return false;
        }
        final Matcher m = START.matcher(request.getServletPath());
        if (!m.matches()) {
            return false;
        }
        try {
            return WalletIdentityProvider.from(registry.get(m.group(1))).isPresent();
        } catch (final RuntimeException e) {
            return false; // no such provider, or the registry failed: never turn a broker start into a 500 here
        }
    }
}
