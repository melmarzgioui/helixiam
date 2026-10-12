/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.e2e;

import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.net.URI;
import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The shared e2e context runs outside the dev profile, so the Host allow-list is on: the request-derived OIDC issuer
 * can no longer be steered with a forged {@code Host} header, and probes still answer. Raw sockets, because the JDK
 * HTTP client does not let a caller set {@code Host}.
 */
class HostAllowListE2eTest extends AbstractE2eTest {

    private static String raw(final String host, final String path) throws IOException {
        final URI base = URI.create(baseUrl());
        try (Socket socket = new Socket("127.0.0.1", base.getPort())) {
            socket.setSoTimeout(10_000);
            final OutputStream out = socket.getOutputStream();
            out.write(("GET " + path + " HTTP/1.1\r\nHost: " + host + "\r\nAccept: application/json\r\n"
                    + "Connection: close\r\n\r\n").getBytes(StandardCharsets.US_ASCII));
            out.flush();
            final InputStream in = socket.getInputStream();
            final ByteArrayOutputStream body = new ByteArrayOutputStream();
            in.transferTo(body);
            return body.toString(StandardCharsets.UTF_8);
        }
    }

    @Test
    void aForgedHost_gets400_andDoesNotChangeTheIssuer() throws Exception {
        final String forged = raw("evil.example", "/realms/" + MASTER + "/.well-known/openid-configuration");

        assertThat(forged).startsWith("HTTP/1.1 400").doesNotContain("\"issuer\"");
        assertThat(oidc(MASTER).discovery().path("issuer").asText()).isEqualTo(baseUrl() + "/realms/" + MASTER);
    }

    @Test
    void theServersOwnHost_isServed() throws Exception {
        final int port = URI.create(baseUrl()).getPort();
        assertThat(raw("localhost:" + port, "/realms/" + MASTER + "/.well-known/openid-configuration"))
                .startsWith("HTTP/1.1 200").contains("\"issuer\":\"" + baseUrl() + "/realms/" + MASTER + "\"");
    }

    @Test
    void aLoopbackProbe_stillWorks() throws Exception {
        final int port = URI.create(baseUrl()).getPort();
        // Docker HEALTHCHECK: curl http://127.0.0.1:$PORT/actuator/health/readiness
        assertThat(raw("127.0.0.1:" + port, "/actuator/health/readiness")).startsWith("HTTP/1.1 200");
        // A kubelet probe carries the pod IP (here: any host) — the health endpoints answer whatever the host.
        assertThat(raw("10.42.0.17:" + port, "/actuator/health/liveness")).startsWith("HTTP/1.1 200");
    }
}
