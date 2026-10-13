/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.session.logout;

import io.helixiam.authorization.federation.UpstreamLogoutClient;
import io.helixiam.testsupport.RebindingTarget;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/** M6: back-channel and upstream logout calls go to the address the guard validated, never a second DNS answer. */
class LogoutRebindingTest {

    @Test
    void theBackChannelLogoutTokenIsPostedToTheValidatedAddressOnly() {
        try (RebindingTarget target = RebindingTarget.http("rp.rebind.test")) {
            new BackchannelLogoutNotifier.HttpPoster(target.guard())
                    .post(target.url("http", "/backchannel_logout"), "eyJ.a.b");

            assertThat(target.requests()).hasSize(1);
            final RebindingTarget.Seen seen = target.requests().get(0);
            assertThat(seen.method()).isEqualTo("POST");
            assertThat(seen.header("Content-Type")).isEqualTo("application/x-www-form-urlencoded");
            assertThat(seen.body()).isEqualTo("logout_token=eyJ.a.b");
            assertThat(target.lookups()).isEqualTo(1);
        }
    }

    @Test
    void theUpstreamLogoutIsFetchedFromTheValidatedAddressOnly() {
        try (RebindingTarget target = RebindingTarget.http("op.rebind.test")) {
            new UpstreamLogoutClient.Http(target.guard()).get(target.url("http", "/logout?id_token_hint=x"));

            assertThat(target.requests()).hasSize(1);
            assertThat(target.requests().get(0).method()).isEqualTo("GET");
            assertThat(target.requests().get(0).path()).isEqualTo("/logout?id_token_hint=x");
            assertThat(target.lookups()).isEqualTo(1);
        }
    }
}
