/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.common.net;

import java.io.IOException;
import java.net.Socket;

/**
 * The socket a {@link PinnedHttpFetcher} worker is using, shared with the caller that aborts it at the deadline.
 * {@link #register} and {@link #abort} are mutually exclusive, and a socket registered after an abort is closed at once
 * (the worker gets a timeout), so no socket can slip past the abort and be connected with nobody left to close it.
 */
final class SocketSlot {

    private Socket current;
    private boolean aborted;

    /** Makes {@code s} the socket an abort closes; refuses (closing {@code s}) once aborted. */
    synchronized void register(final Socket s) throws PinnedHttpFetcher.FetchException {
        if (aborted) {
            close(s);
            throw new PinnedHttpFetcher.FetchException(PinnedHttpFetcher.FetchException.Kind.TIMEOUT,
                    "fetch timed out");
        }
        current = s;
    }

    /** Marks the fetch aborted and closes its socket, if any. */
    synchronized void abort() {
        aborted = true;
        close(current);
    }

    synchronized boolean aborted() {
        return aborted;
    }

    synchronized Socket current() {
        return current;
    }

    static void close(final Socket s) {
        if (s == null) {
            return;
        }
        try {
            s.close();
        } catch (final IOException e) {
            // nothing to do
        }
    }
}
