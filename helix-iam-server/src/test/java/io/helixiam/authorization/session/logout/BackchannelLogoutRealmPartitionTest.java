/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.session.logout;

import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

import static org.assertj.core.api.Assertions.assertThat;

/** Back-channel logout names the session's realm on every POST, so the fetch counts against that realm's share. */
class BackchannelLogoutRealmPartitionTest {

    @Test
    void theRealmOfTheSessionIsPassedToThePoster() {
        final List<String> realms = new CopyOnWriteArrayList<>();
        final BackchannelLogoutNotifier.Poster poster = new BackchannelLogoutNotifier.RealmAwarePoster() {
            @Override
            public void post(final String uri, final String logoutToken) {
                realms.add("(none)");
            }

            @Override
            public void post(final String realm, final String uri, final String logoutToken) {
                realms.add(realm);
            }
        };
        final LogoutTokenIssuer issuer = Mockito.mock(LogoutTokenIssuer.class);
        Mockito.when(issuer.issue(Mockito.any(), Mockito.any(), Mockito.any(), Mockito.any(), Mockito.any()))
                .thenReturn("jwt");
        new BackchannelLogoutNotifier(issuer, poster).notifyClients("acme", "https://idp/realms/acme", "sub", "sid",
                List.of(new BackchannelLogoutNotifier.Target("c1", "https://rp.example/bcl")));
        assertThat(realms).containsExactly("acme");
    }
}
