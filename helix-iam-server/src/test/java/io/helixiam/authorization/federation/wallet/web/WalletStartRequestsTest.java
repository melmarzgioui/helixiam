/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.wallet.web;

import io.helixiam.authorization.federation.IdentityProviderRegistry;
import io.helixiam.authorization.federation.spi.IdentityProvider;
import io.helixiam.authorization.federation.wallet.WalletIdentityProvider;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/** Task 18 fix round 1: which requests the wallet-start rate limit counts ({@code GET /broker/<wallet alias>}). */
class WalletStartRequestsTest {

    private final IdentityProviderRegistry registry = mock(IdentityProviderRegistry.class);

    WalletStartRequestsTest() {
        when(registry.get(any(), eq("eudi"))).thenReturn(mock(WalletIdentityProvider.class));
        when(registry.get(any(), eq("corp"))).thenReturn(mock(IdentityProvider.class));
        when(registry.get(any(), eq("nope"))).thenThrow(new IllegalArgumentException("No identity provider"));
        when(registry.get(any(), eq("broken"))).thenThrow(new IllegalStateException("registry reload in progress"));
    }

    private boolean counts(final String method, final String servletPath) {
        final MockHttpServletRequest request = new MockHttpServletRequest(method, "/realms/acme" + servletPath);
        request.setServletPath(servletPath);
        return WalletStartRequests.isWalletStart(request, registry);
    }

    @Test
    void onlyTheStartOfAWalletProvider_counts() {
        assertThat(counts("GET", "/broker/eudi")).isTrue();
        assertThat(counts("GET", "/broker/corp")).isFalse();
        assertThat(counts("GET", "/broker/nope")).isFalse();
        assertThat(counts("GET", "/broker/eudi/callback")).isFalse();
        assertThat(counts("GET", "/broker/eudi/wallet")).isFalse();
        assertThat(counts("POST", "/broker/eudi")).isFalse();
        assertThat(counts("GET", "/login")).isFalse();
    }

    /** Fix round 2: a registry failure is "not a wallet start": the rate limit never turns it into a 500. */
    @Test
    void aRegistryFailure_isNotAWalletStart() {
        assertThat(counts("GET", "/broker/broken")).isFalse();
    }
}
