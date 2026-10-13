/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.ldap;

import javax.net.SocketFactory;
import javax.net.ssl.SSLSocketFactory;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * The JNDI LDAP socket factory ({@code java.naming.ldap.factory.socket}) for {@link JndiLdapDirectory}. JNDI looks
 * the factory up by class name and calls the static {@link #getDefault()}, so the validated target travels in a
 * thread-local that {@link JndiLdapDirectory} sets around each bind on the calling thread. Every socket connects to
 * one of the validated addresses, never to a fresh lookup of the name. For {@code ldaps} TLS is layered with the
 * configured host name, which JNDI then verifies ({@code LDAPS} endpoint identification). Outside a bind there is no
 * target and every socket is refused.
 */
public final class PinnedLdapSocketFactory extends SocketFactory {

    /** At most this many of the addresses a name resolves to are tried (a name with many dead A records). */
    static final int MAX_ADDRESSES = 2;

    /** Where the current bind sequence may connect, until when, and how to abort it. */
    record Target(List<InetAddress> addresses, int port, int connectTimeoutMillis, SSLSocketFactory tls,
                  long deadlineNanos, Abort abort) {
    }

    /** Closes every socket of one bind sequence at its deadline, and refuses new ones after that. */
    static final class Abort {
        private final List<Socket> sockets = new CopyOnWriteArrayList<>();
        private volatile boolean aborted;

        void register(final Socket socket) throws IOException {
            sockets.add(socket);
            if (aborted) {
                closeQuietly(socket);
                throw new IOException("LDAP bind sequence aborted at its deadline");
            }
        }

        boolean aborted() {
            return aborted;
        }

        void abort() {
            aborted = true;
            sockets.forEach(PinnedLdapSocketFactory::closeQuietly);
        }
    }

    /** The first {@link #MAX_ADDRESSES} addresses. */
    static List<InetAddress> toTry(final List<InetAddress> addresses) {
        return addresses.size() <= MAX_ADDRESSES ? addresses : addresses.subList(0, MAX_ADDRESSES);
    }

    private static final ThreadLocal<Target> CURRENT = new ThreadLocal<>();

    private final Target target;

    private PinnedLdapSocketFactory(final Target target) {
        this.target = target;
    }

    /** Called by JNDI. */
    public static SocketFactory getDefault() {
        return new PinnedLdapSocketFactory(CURRENT.get());
    }

    static void set(final Target target) {
        CURRENT.set(target);
    }

    static void clear() {
        CURRENT.remove();
    }

    @Override
    public Socket createSocket(final String host, final int port) throws IOException {
        if (target == null) {
            throw new IOException("No validated LDAP target");
        }
        IOException last = null;
        for (final InetAddress address : toTry(target.addresses())) {
            final long left = java.util.concurrent.TimeUnit.NANOSECONDS.toMillis(
                    target.deadlineNanos() - System.nanoTime());
            if (left <= 0 || target.abort().aborted()) {
                throw new IOException("LDAP bind sequence deadline passed");
            }
            final Socket socket = new Socket();
            target.abort().register(socket);
            try {
                socket.connect(new InetSocketAddress(address, target.port()),
                        (int) Math.max(1, Math.min(target.connectTimeoutMillis(), left)));
            } catch (final IOException e) {
                closeQuietly(socket);
                last = e;
                continue;
            }
            if (target.tls() == null) {
                return socket;
            }
            try {
                return target.tls().createSocket(socket, host, target.port(), true);
            } catch (final IOException e) {
                closeQuietly(socket);
                throw e;
            }
        }
        throw last != null ? last : new IOException("No validated LDAP address");
    }

    @Override
    public Socket createSocket(final String host, final int port, final InetAddress localHost, final int localPort)
            throws IOException {
        return createSocket(host, port);
    }

    @Override
    public Socket createSocket(final InetAddress host, final int port) throws IOException {
        return createSocket(host.getHostAddress(), port);
    }

    @Override
    public Socket createSocket(final InetAddress address, final int port, final InetAddress localAddress,
            final int localPort) throws IOException {
        return createSocket(address.getHostAddress(), port);
    }

    static void closeQuietly(final Socket socket) {
        try {
            socket.close();
        } catch (final IOException ignored) {
            // best effort
        }
    }
}
