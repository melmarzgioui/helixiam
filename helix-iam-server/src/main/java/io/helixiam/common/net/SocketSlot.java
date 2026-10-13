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

    private final java.util.List<Socket> sockets = new java.util.ArrayList<>(2);
    private boolean aborted;

    /** Makes {@code s} the socket an abort closes; refuses (closing {@code s}) once aborted. */
    void register(final Socket s) throws PinnedHttpFetcher.FetchException {
        synchronized (this) {
            if (!aborted) {
                sockets.add(s);
                return;
            }
        }
        close(s);
        throw new PinnedHttpFetcher.FetchException(PinnedHttpFetcher.FetchException.Kind.TIMEOUT, "fetch timed out");
    }

    /**
     * Marks the fetch aborted and closes its sockets, outside the lock and plain TCP sockets first: closing an
     * {@code SSLSocket} can wait for a read in progress, closing the socket under it never does.
     */
    void abort() {
        final java.util.List<Socket> toClose;
        synchronized (this) {
            aborted = true;
            toClose = new java.util.ArrayList<>(sockets);
        }
        toClose.stream().filter(s -> !(s instanceof javax.net.ssl.SSLSocket)).forEach(SocketSlot::close);
        toClose.stream().filter(s -> s instanceof javax.net.ssl.SSLSocket).forEach(SocketSlot::close);
    }

    synchronized boolean aborted() {
        return aborted;
    }

    /** The socket registered last (the one in use), or null. */
    synchronized Socket current() {
        return sockets.isEmpty() ? null : sockets.get(sockets.size() - 1);
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
