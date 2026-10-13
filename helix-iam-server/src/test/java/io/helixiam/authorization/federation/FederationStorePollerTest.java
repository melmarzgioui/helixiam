/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/** The store poll reloads changed realms and survives a failing poll (retried at the next one). */
class FederationStorePollerTest {

    @Test
    void aPollReloadsTheChangedRealms() {
        final FederationStoreRefresher refresher = mock(FederationStoreRefresher.class);

        new FederationStorePoller(refresher, 60).poll();

        verify(refresher).refreshChanged();
    }

    @Test
    void aFailingPoll_doesNotStopThePoller() {
        final FederationStoreRefresher refresher = mock(FederationStoreRefresher.class);
        when(refresher.refreshChanged()).thenThrow(new IllegalStateException("database down"));

        assertThatCode(() -> new FederationStorePoller(refresher, 60).poll()).doesNotThrowAnyException();
    }
}
