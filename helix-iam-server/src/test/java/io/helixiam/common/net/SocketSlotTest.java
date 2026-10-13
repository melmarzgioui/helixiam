/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.common.net;

import org.junit.jupiter.api.Test;

import java.net.Socket;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * The abort / socket hand-over in {@link PinnedHttpFetcher}: a socket registered after the caller aborted (the race
 * between {@code abort()} closing the current socket and the worker registering a new one) is closed at once and the
 * worker stops, instead of connecting with nobody left to close it.
 */
class SocketSlotTest {

    @Test
    void aSocketRegisteredAfterTheAbortIsClosedAndTheWorkerStops() throws Exception {
        final SocketSlot slot = new SocketSlot();
        slot.abort();
        final Socket late = new Socket();

        assertThatThrownBy(() -> slot.register(late)).isInstanceOfSatisfying(PinnedHttpFetcher.FetchException.class,
                e -> assertThat(e.kind()).isEqualTo(PinnedHttpFetcher.FetchException.Kind.TIMEOUT));
        assertThat(late.isClosed()).isTrue();
    }

    @Test
    void anAbortClosesTheRegisteredSocket() throws Exception {
        final SocketSlot slot = new SocketSlot();
        final Socket current = new Socket();
        slot.register(current);
        assertThat(current.isClosed()).isFalse();

        slot.abort();

        assertThat(current.isClosed()).isTrue();
        assertThat(slot.aborted()).isTrue();
    }
}
