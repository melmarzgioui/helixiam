/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.testsupport;

import jakarta.mail.Session;
import jakarta.mail.internet.MimeMessage;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.UncheckedIOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Properties;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Predicate;

/**
 * A minimal local SMTP server for driver tests: plain, plain with STARTTLS, or TLS-only (implicit TLS, "SMTPS"). It
 * accepts AUTH PLAIN / LOGIN with any credentials (recording them), can answer a chosen reply to AUTH, MAIL FROM,
 * RCPT TO or DATA (to exercise the 4xx / 5xx classification), and keeps every received message.
 */
public final class TestSmtpServer implements AutoCloseable {

    /** How the server protects the connection. */
    public enum Mode { PLAIN, STARTTLS, IMPLICIT_TLS }

    /** One received message and the session details around it. */
    public record Received(String mailFrom, List<String> rcptTo, String raw, boolean tls, String authUser,
                           String authPassword, String ehlo) {

        public MimeMessage mime() {
            try {
                return new MimeMessage(Session.getInstance(new Properties()),
                        new ByteArrayInputStream(raw.getBytes(StandardCharsets.UTF_8)));
            } catch (final Exception e) {
                throw new IllegalStateException(e);
            }
        }
    }

    private final Mode mode;
    private final SSLContext tls;
    private final ServerSocket server;
    private final List<Received> received = new CopyOnWriteArrayList<>();
    private final List<String> commands = new CopyOnWriteArrayList<>();
    private volatile String authReply = "235 2.7.0 Authentication successful";
    private volatile String mailReply = "250 2.1.0 Ok";
    private volatile String rcptReply = "250 2.1.5 Ok";
    private volatile String dataReply = "250 2.0.0 Ok: queued as TEST123";
    private volatile boolean running = true;

    private TestSmtpServer(final Mode mode, final SSLContext tls) throws IOException {
        this.mode = mode;
        this.tls = tls;
        final InetAddress loopback = InetAddress.getByAddress(new byte[] {127, 0, 0, 1});
        this.server = mode == Mode.IMPLICIT_TLS
                ? tls.getServerSocketFactory().createServerSocket(0, 50, loopback)
                : new ServerSocket();
        if (mode != Mode.IMPLICIT_TLS) {
            server.bind(new InetSocketAddress(loopback, 0));
        }
        final Thread acceptor = new Thread(this::acceptLoop, "test-smtp-" + mode);
        acceptor.setDaemon(true);
        acceptor.start();
    }

    /** A plain server that does not offer STARTTLS. */
    public static TestSmtpServer plain() {
        return start(Mode.PLAIN, null);
    }

    /** A plain server that offers STARTTLS with {@code tls}'s certificate. */
    public static TestSmtpServer startTls(final TestTls tls) {
        return start(Mode.STARTTLS, tls.serverContext());
    }

    /** A TLS-only server (implicit TLS) with {@code tls}'s certificate. */
    public static TestSmtpServer implicitTls(final TestTls tls) {
        return start(Mode.IMPLICIT_TLS, tls.serverContext());
    }

    private static TestSmtpServer start(final Mode mode, final SSLContext tls) {
        try {
            return new TestSmtpServer(mode, tls);
        } catch (final IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    public int port() {
        return server.getLocalPort();
    }

    public TestSmtpServer replyToAuth(final String reply) {
        this.authReply = reply;
        return this;
    }

    public TestSmtpServer replyToMailFrom(final String reply) {
        this.mailReply = reply;
        return this;
    }

    public TestSmtpServer replyToRcpt(final String reply) {
        this.rcptReply = reply;
        return this;
    }

    public TestSmtpServer replyToData(final String reply) {
        this.dataReply = reply;
        return this;
    }

    public List<Received> received() {
        return List.copyOf(received);
    }

    /** Every command line the server read (AUTH arguments masked). */
    public List<String> commands() {
        return List.copyOf(commands);
    }

    /** Waits for a message matching {@code filter}; returns the latest match. */
    public Received await(final Predicate<Received> filter, final Duration timeout) {
        final Instant deadline = Instant.now().plus(timeout);
        do {
            final List<Received> matching = received.stream().filter(filter).toList();
            if (!matching.isEmpty()) {
                return matching.get(matching.size() - 1);
            }
            try {
                Thread.sleep(50);
            } catch (final InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new IllegalStateException(e);
            }
        } while (Instant.now().isBefore(deadline));
        throw new AssertionError("No matching message within " + timeout + "; received " + received.size());
    }

    private void acceptLoop() {
        while (running) {
            try {
                final Socket socket = server.accept();
                final Thread t = new Thread(() -> handle(socket), "test-smtp-session");
                t.setDaemon(true);
                t.start();
            } catch (final IOException e) {
                if (!running) {
                    return;
                }
            }
        }
    }

    private void handle(final Socket initial) {
        Socket socket = initial;
        try {
            socket.setSoTimeout(15_000);
            boolean secure = mode == Mode.IMPLICIT_TLS;
            if (secure) {
                ((SSLSocket) socket).startHandshake();
            }
            BufferedReader in = reader(socket);
            OutputStream out = socket.getOutputStream();
            reply(out, "220 localhost ESMTP test");
            String mailFrom = null;
            final List<String> rcpt = new ArrayList<>();
            String authUser = null;
            String authPassword = null;
            String ehlo = null;
            String line;
            while ((line = in.readLine()) != null) {
                final String upper = line.toUpperCase(java.util.Locale.ROOT);
                commands.add(upper.startsWith("AUTH") ? "AUTH ***" : line);
                if (upper.startsWith("EHLO") || upper.startsWith("HELO")) {
                    ehlo = line.length() > 5 ? line.substring(5).trim() : "";
                    final StringBuilder caps = new StringBuilder("250-localhost\r\n");
                    if (mode == Mode.STARTTLS && !secure) {
                        caps.append("250-STARTTLS\r\n");
                    }
                    caps.append("250-AUTH PLAIN LOGIN\r\n250 8BITMIME");
                    reply(out, caps.toString());
                } else if (upper.startsWith("STARTTLS") && mode == Mode.STARTTLS && !secure) {
                    reply(out, "220 2.0.0 Ready to start TLS");
                    final SSLSocket ssl = (SSLSocket) tls.getSocketFactory().createSocket(socket,
                            socket.getInetAddress().getHostAddress(), socket.getPort(), true);
                    ssl.setUseClientMode(false);
                    ssl.startHandshake();
                    socket = ssl;
                    secure = true;
                    in = reader(socket);
                    out = socket.getOutputStream();
                } else if (upper.startsWith("AUTH PLAIN")) {
                    String arg = line.length() > 10 ? line.substring(10).trim() : "";
                    if (arg.isEmpty()) {
                        reply(out, "334 ");
                        arg = in.readLine();
                    }
                    final String[] parts = new String(Base64.getDecoder().decode(arg.trim()), StandardCharsets.UTF_8)
                            .split("\u0000", -1);
                    authUser = parts.length > 1 ? parts[1] : null;
                    authPassword = parts.length > 2 ? parts[2] : null;
                    reply(out, authReply);
                } else if (upper.startsWith("AUTH LOGIN")) {
                    reply(out, "334 VXNlcm5hbWU6");
                    authUser = new String(Base64.getDecoder().decode(in.readLine().trim()), StandardCharsets.UTF_8);
                    reply(out, "334 UGFzc3dvcmQ6");
                    authPassword = new String(Base64.getDecoder().decode(in.readLine().trim()), StandardCharsets.UTF_8);
                    reply(out, authReply);
                } else if (upper.startsWith("MAIL FROM")) {
                    mailFrom = line.substring(line.indexOf(':') + 1).trim();
                    rcpt.clear();
                    reply(out, mailReply);
                } else if (upper.startsWith("RCPT TO")) {
                    rcpt.add(line.substring(line.indexOf(':') + 1).trim());
                    reply(out, rcptReply);
                } else if (upper.startsWith("DATA")) {
                    reply(out, "354 End data with <CR><LF>.<CR><LF>");
                    final StringBuilder data = new StringBuilder();
                    String d;
                    while ((d = in.readLine()) != null && !".".equals(d)) {
                        data.append(d.startsWith("..") ? d.substring(1) : d).append("\r\n");
                    }
                    if (dataReply.startsWith("2")) {
                        received.add(new Received(mailFrom, List.copyOf(rcpt), data.toString(), secure, authUser,
                                authPassword, ehlo));
                    }
                    reply(out, dataReply);
                } else if (upper.startsWith("RSET")) {
                    rcpt.clear();
                    reply(out, "250 2.0.0 Ok");
                } else if (upper.startsWith("NOOP")) {
                    reply(out, "250 2.0.0 Ok");
                } else if (upper.startsWith("QUIT")) {
                    reply(out, "221 2.0.0 Bye");
                    break;
                } else {
                    reply(out, "502 5.5.2 Command not recognized");
                }
            }
        } catch (final IOException e) {
            // the client hung up (e.g. a failed TLS handshake): fine
        } finally {
            try {
                socket.close();
            } catch (final IOException ignored) {
                // closing
            }
        }
    }

    private static BufferedReader reader(final Socket socket) throws IOException {
        return new BufferedReader(new InputStreamReader(socket.getInputStream(), StandardCharsets.UTF_8));
    }

    private static void reply(final OutputStream out, final String text) throws IOException {
        out.write((text + "\r\n").getBytes(StandardCharsets.UTF_8));
        out.flush();
    }

    @Override
    public void close() {
        running = false;
        try {
            server.close();
        } catch (final IOException ignored) {
            // closing
        }
    }
}
