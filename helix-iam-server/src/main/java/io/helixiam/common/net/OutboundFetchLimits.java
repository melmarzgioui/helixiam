/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.common.net;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/**
 * Sizes the per-group outbound limiters ({@link FetchLimiter.Group}) at startup:
 * {@code helix.outbound.fetch.<group>.max-concurrent} and {@code helix.outbound.fetch.<group>.per-realm-max} for
 * {@code wallet}, {@code login-admin} (old name {@code login}), {@code login-client}, {@code otp} and {@code outbound}. The wallet group also reads the older
 * {@code helix.wallet.fetch.max-concurrent} when the new name is not set.
 */
@Component
public class OutboundFetchLimits {

    public OutboundFetchLimits(
            @Value("${helix.outbound.fetch.wallet.max-concurrent:${helix.wallet.fetch.max-concurrent:16}}")
            final int walletMax,
            @Value("${helix.outbound.fetch.wallet.per-realm-max:${helix.outbound.fetch.wallet.max-concurrent:"
                    + "${helix.wallet.fetch.max-concurrent:16}}}") final int walletPerRealm,
            @Value("${helix.outbound.fetch.login-admin.max-concurrent:${helix.outbound.fetch.login.max-concurrent:32}}")
            final int loginMax,
            @Value("${helix.outbound.fetch.login-admin.per-realm-max:${helix.outbound.fetch.login.per-realm-max:8}}")
            final int loginPerRealm,
            @Value("${helix.outbound.fetch.login-client.max-concurrent:32}") final int loginClientMax,
            @Value("${helix.outbound.fetch.login-client.per-realm-max:8}") final int loginClientPerRealm,
            @Value("${helix.outbound.fetch.otp.max-concurrent:32}") final int otpMax,
            @Value("${helix.outbound.fetch.otp.per-realm-max:8}") final int otpPerRealm,
            @Value("${helix.outbound.fetch.outbound.max-concurrent:32}") final int outboundMax,
            @Value("${helix.outbound.fetch.outbound.per-realm-max:8}") final int outboundPerRealm) {
        FetchLimiter.forGroup(FetchLimiter.Group.WALLET).configure(walletMax, walletPerRealm);
        FetchLimiter.forGroup(FetchLimiter.Group.LOGIN_ADMIN).configure(loginMax, loginPerRealm);
        FetchLimiter.forGroup(FetchLimiter.Group.LOGIN_CLIENT).configure(loginClientMax, loginClientPerRealm);
        FetchLimiter.forGroup(FetchLimiter.Group.OTP).configure(otpMax, otpPerRealm);
        FetchLimiter.forGroup(FetchLimiter.Group.OUTBOUND).configure(outboundMax, outboundPerRealm);
    }
}
