/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.common.net;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

import static org.assertj.core.api.Assertions.assertThat;

/** The per-group sizes come from helix.outbound.fetch.*; the old wallet-only name still works as an alias. */
class OutboundFetchLimitsTest {

    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withBean(OutboundFetchLimits.class);

    @AfterEach
    void defaults() {
        for (final FetchLimiter.Group g : FetchLimiter.Group.values()) {
            FetchLimiter.forGroup(g).configure(g.defaultMax(), g.defaultPerRealmMax());
        }
    }

    @Test
    void eachGroupIsSizedOnItsOwn() {
        runner.withPropertyValues("helix.outbound.fetch.login.max-concurrent=40",
                "helix.outbound.fetch.login.per-realm-max=5", "helix.outbound.fetch.otp.max-concurrent=12",
                "helix.outbound.fetch.outbound.per-realm-max=3").run(ctx -> {
                    assertThat(FetchLimiter.forGroup(FetchLimiter.Group.LOGIN_ADMIN).max()).isEqualTo(40);
                    assertThat(FetchLimiter.forGroup(FetchLimiter.Group.LOGIN_ADMIN).perPartitionMax()).isEqualTo(5);
                    assertThat(FetchLimiter.forGroup(FetchLimiter.Group.OTP).max()).isEqualTo(12);
                    assertThat(FetchLimiter.forGroup(FetchLimiter.Group.OUTBOUND).perPartitionMax()).isEqualTo(3);
                    assertThat(FetchLimiter.forGroup(FetchLimiter.Group.WALLET).max()).isEqualTo(16);
                });
    }

    @Test
    void theOldWalletNameIsAnAliasAndTheNewNameWins() {
        runner.withPropertyValues("helix.wallet.fetch.max-concurrent=7").run(ctx ->
                assertThat(FetchLimiter.forGroup(FetchLimiter.Group.WALLET).max()).isEqualTo(7));
        runner.withPropertyValues("helix.wallet.fetch.max-concurrent=7",
                "helix.outbound.fetch.wallet.max-concurrent=9").run(ctx ->
                assertThat(FetchLimiter.forGroup(FetchLimiter.Group.WALLET).max()).isEqualTo(9));
    }
}
