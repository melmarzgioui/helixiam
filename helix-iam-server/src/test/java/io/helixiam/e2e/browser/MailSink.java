/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.e2e.browser;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Predicate;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * A fake HTTP email API (the "HTTP" email driver's target, as Monthfold runs it). One per JVM, like the IdP: the
 * reference realm's EMAIL provider posts {@code {from, fromName, to, subject, body, html, contentType, text}} JSON to
 * {@link #url()}, and tests read what was "sent" with {@link #await}.
 *
 * <p>Magic-link emails never reach it: the e2e context swaps the magic-link sender for
 * {@code CapturingMagicLinkSender} ({@code helix.e2e.capture-magic-links}); read those with
 * {@code CapturingMagicLinkSender.linksFor(email)}.
 */
public final class MailSink {

    private static final ObjectMapper JSON = new ObjectMapper();
    private static final Pattern LINK = Pattern.compile("https?://[^\\s\"'<>]+");
    private static MailSink instance;

    private final HttpServer server;
    private final List<CapturedEmail> received = new CopyOnWriteArrayList<>();

    private MailSink() throws IOException {
        server = HttpServer.create(new InetSocketAddress(InetAddress.getByAddress(new byte[] {127, 0, 0, 1}), 0), 0);
        server.createContext("/mail", this::handle);
        server.start();
        HarnessEgressGuard.allow(port());
    }

    /** The JVM-wide sink (started on first use, stopped at JVM exit). */
    public static synchronized MailSink get() {
        if (instance == null) {
            try {
                instance = new MailSink();
            } catch (final IOException e) {
                throw new UncheckedIOException(e);
            }
            final MailSink started = instance;
            Runtime.getRuntime().addShutdownHook(new Thread(() -> started.server.stop(0)));
        }
        return instance;
    }

    public int port() {
        return server.getAddress().getPort();
    }

    /** The URL to configure as an HTTP email provider's {@code config.url}. */
    public String url() {
        return "http://127.0.0.1:" + port() + "/mail";
    }

    /** Every message sent to {@code to} so far (case-insensitive), oldest first. */
    public List<CapturedEmail> emailsTo(final String to) {
        return received.stream().filter(m -> m.to() != null && m.to().equalsIgnoreCase(to)).toList();
    }

    /** Waits up to {@code timeout} for a message to {@code to} matching {@code filter}; returns the latest match. */
    public CapturedEmail await(final String to, final Predicate<CapturedEmail> filter, final Duration timeout) {
        final Instant deadline = Instant.now().plus(timeout);
        do {
            final List<CapturedEmail> matching = emailsTo(to).stream().filter(filter).toList();
            if (!matching.isEmpty()) {
                return matching.get(matching.size() - 1);
            }
            sleep(100);
        } while (Instant.now().isBefore(deadline));
        throw new AssertionError("No email to " + to + " within " + timeout + "; the sink received: "
                + received.stream().map(m -> m.to() + " / " + m.subject()).toList());
    }

    private void handle(final HttpExchange exchange) throws IOException {
        try (exchange; InputStream in = exchange.getRequestBody()) {
            if (!"POST".equals(exchange.getRequestMethod())) {
                exchange.sendResponseHeaders(405, -1);
                return;
            }
            final JsonNode m = JSON.readTree(new String(in.readAllBytes(), StandardCharsets.UTF_8));
            received.add(new CapturedEmail(m.path("from").asText(null), m.path("to").asText(null),
                    m.path("subject").asText(""), m.path("body").asText(""), m.path("html").asBoolean(false),
                    m.path("text").asText(null), exchange.getRequestHeaders().getFirst("Authorization"), Instant.now()));
            exchange.sendResponseHeaders(202, -1);
        }
    }

    private static void sleep(final long millis) {
        try {
            Thread.sleep(millis);
        } catch (final InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException(e);
        }
    }

    /** One message the IdP handed to the HTTP email API. */
    public record CapturedEmail(String from, String to, String subject, String body, boolean html, String text,
                                String authorization, Instant at) {

        /** Every http(s) URL in the body ({@code &amp;} decoded), in order. */
        public List<String> links() {
            final Matcher m = LINK.matcher(body);
            final List<String> out = new java.util.ArrayList<>();
            while (m.find()) {
                out.add(m.group().replace("&amp;", "&"));
            }
            return out;
        }

        /** The first link whose URL contains {@code fragment}. */
        public Optional<String> link(final String fragment) {
            return links().stream().filter(l -> l.contains(fragment)).findFirst();
        }
    }
}
