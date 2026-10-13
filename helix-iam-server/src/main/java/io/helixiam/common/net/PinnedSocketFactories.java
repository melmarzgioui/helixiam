/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.common.net;

import javax.net.SocketFactory;
import javax.net.ssl.SSLSocketFactory;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketAddress;
import java.util.Objects;

/**
 * Socket factories that connect to one address the outbound guard validated, whatever host the client library asks
 * for, for protocol clients that cannot use {@link PinnedHttpFetcher} (Jakarta Mail SMTP, JNDI LDAP). The library
 * still works with the configured host name, so TLS (STARTTLS, SMTPS, LDAPS) is layered over the pinned socket with
 * that name as SNI and checked against it: {@link Ssl#createSocket(Socket, String, int, boolean)} delegates to the real
 * TLS factory with the name the library passes. No second DNS answer is ever connected to.
 */
public final class PinnedSocketFactories {

    private PinnedSocketFactories() {
    }

    /** A socket whose connect goes to the pinned address and port, whatever endpoint it is given. */
    static final class PinnedSocket extends Socket {
        private final InetSocketAddress pinned;

        PinnedSocket(final InetSocketAddress pinned) {
            this.pinned = pinned;
        }

        @Override
        public void connect(final SocketAddress endpoint, final int timeout) throws IOException {
            super.connect(pinned, timeout);
        }

        @Override
        public void connect(final SocketAddress endpoint) throws IOException {
            super.connect(pinned, 0);
        }
    }

    /** Plain sockets to the pinned address (SMTP before STARTTLS, LDAP without TLS). */
    public static final class Plain extends SocketFactory {
        private final InetSocketAddress pinned;
        private final int connectTimeoutMillis;

        public Plain(final InetAddress address, final int port, final int connectTimeoutMillis) {
            this.pinned = new InetSocketAddress(Objects.requireNonNull(address, "address"), port);
            this.connectTimeoutMillis = connectTimeoutMillis;
        }

        @Override
        public Socket createSocket() {
            return new PinnedSocket(pinned);
        }

        private Socket connected() throws IOException {
            final Socket s = new PinnedSocket(pinned);
            s.connect(pinned, connectTimeoutMillis);
            return s;
        }

        @Override
        public Socket createSocket(final String host, final int port) throws IOException {
            return connected();
        }

        @Override
        public Socket createSocket(final String host, final int port, final InetAddress localHost, final int localPort)
                throws IOException {
            return connected();
        }

        @Override
        public Socket createSocket(final InetAddress host, final int port) throws IOException {
            return connected();
        }

        @Override
        public Socket createSocket(final InetAddress address, final int port, final InetAddress localAddress,
                final int localPort) throws IOException {
            return connected();
        }
    }

    /**
     * TLS over a pinned socket: an unconnected socket is a plain pinned one (the library connects it and then layers
     * TLS through {@link #createSocket(Socket, String, int, boolean)}); a connected request connects the pinned socket
     * and layers TLS for the given host name.
     */
    public static final class Ssl extends SSLSocketFactory {
        private final Plain plain;
        private final SSLSocketFactory tls;

        public Ssl(final InetAddress address, final int port, final int connectTimeoutMillis,
                final SSLSocketFactory tls) {
            this.plain = new Plain(address, port, connectTimeoutMillis);
            this.tls = Objects.requireNonNull(tls, "tls");
        }

        @Override
        public Socket createSocket() {
            return plain.createSocket();
        }

        @Override
        public Socket createSocket(final Socket s, final String host, final int port, final boolean autoClose)
                throws IOException {
            return tls.createSocket(s, host, port, autoClose); // SNI and the identity check use the configured name
        }

        @Override
        public Socket createSocket(final String host, final int port) throws IOException {
            return tls.createSocket(plain.createSocket(host, port), host, port, true);
        }

        @Override
        public Socket createSocket(final String host, final int port, final InetAddress localHost, final int localPort)
                throws IOException {
            return createSocket(host, port);
        }

        @Override
        public Socket createSocket(final InetAddress host, final int port) throws IOException {
            return tls.createSocket(plain.createSocket(host, port), host.getHostAddress(), port, true);
        }

        @Override
        public Socket createSocket(final InetAddress address, final int port, final InetAddress localAddress,
                final int localPort) throws IOException {
            return createSocket(address, port);
        }

        @Override
        public String[] getDefaultCipherSuites() {
            return tls.getDefaultCipherSuites();
        }

        @Override
        public String[] getSupportedCipherSuites() {
            return tls.getSupportedCipherSuites();
        }
    }
}
