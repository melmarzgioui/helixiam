/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.messaging.driver;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.helixiam.authorization.amqp.messaging.ResolvedProviderDto;
import io.helixiam.authorization.messaging.EmailText;
import org.springframework.stereotype.Component;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Helix IAM notifications (N3): a generic HTTP email-API driver (SendGrid / SES-style) for setups that block
 * SMTP. {@code config.url} is the endpoint; the JSON body carries {@code from/fromName/to/subject/body/html/contentType}
 * and {@code text} (the plain-text part; for an HTML email, its text alternative with every link); {@code secret}
 * is sent as the {@code Authorization} header value (default {@code Bearer }-prefixed; overridable via
 * {@code config.authHeader}/{@code config.authScheme}).
 */
@Component
public class HttpEmailDriver implements EmailDriver {

    private final HttpTransport http;
    private final ObjectMapper objectMapper = new ObjectMapper();

    public HttpEmailDriver(final HttpTransport http) {
        this.http = http;
    }

    @Override
    public String driver() {
        return "HTTP";
    }

    @Override
    public void send(final ResolvedProviderDto provider, final String to, final String subject, final String body,
                     final boolean html) {
        send(provider, to, subject, body, html, null);
    }

    /**
     * The payload also carries {@code text}: the plain-text part (for an HTML email {@code text}, else derived from
     * the HTML; for a plain email the body), for APIs that send {@code multipart/alternative} (item 3).
     */
    @Override
    public void send(final ResolvedProviderDto provider, final String to, final String subject, final String body,
                     final boolean html, final String text) {
        final Map<String, String> config = provider.config() == null ? Map.of() : provider.config();
        final String url = config.get("url");
        if (url == null || url.isBlank()) {
            throw new IllegalStateException("HTTP email provider is missing url");
        }
        final ObjectNode json = objectMapper.createObjectNode();
        json.put("from", provider.fromAddress());
        json.put("fromName", provider.fromName());
        json.put("to", to);
        json.put("subject", subject == null ? "" : subject);
        json.put("body", body == null ? "" : body);
        // Content type signal for the API: html=true means the body is text/html (an "html" field is also set so
        // SendGrid/SES-style APIs that key off a dedicated HTML field pick it up directly).
        json.put("html", html);
        json.put("contentType", html ? "text/html" : "text/plain");
        json.put("text", html ? (text != null ? text : EmailText.fromHtml(body)) : (body == null ? "" : body));
        final String payload;
        try {
            payload = objectMapper.writeValueAsString(json);
        } catch (final Exception e) {
            throw new IllegalStateException("Could not build email payload: " + e.getMessage(), e);
        }
        final Map<String, String> headers = new LinkedHashMap<>();
        headers.put("Content-Type", "application/json");
        if (provider.secret() != null && !provider.secret().isBlank()) {
            headers.put(config.getOrDefault("authHeader", "Authorization"),
                    config.getOrDefault("authScheme", "Bearer ") + provider.secret());
        }
        final int status = http.post(url, headers, payload);
        if (status >= 300) {
            throw new IllegalStateException("HTTP email API rejected the message (HTTP " + status + ")");
        }
    }
}
