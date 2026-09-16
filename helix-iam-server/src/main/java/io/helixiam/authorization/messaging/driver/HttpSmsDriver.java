/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.messaging.driver;

import io.helixiam.authorization.amqp.messaging.ResolvedProviderDto;
import io.helixiam.authorization.messaging.TemplateRenderer;
import org.springframework.stereotype.Component;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Helix IAM notifications (N3): a generic HTTP-webhook SMS driver so any gateway works without vendor code.
 * {@code config.url} is the endpoint; {@code config.bodyTemplate} is the request body with {@code {{to}}} /
 * {@code {{message}}} placeholders; {@code config.contentType} (default JSON) and {@code config.authHeader}
 * (default {@code Authorization}) shape the request; {@code secret} is sent as that header's value (prefixed
 * {@code Bearer } unless {@code config.authScheme} says otherwise).
 */
@Component
public class HttpSmsDriver implements SmsDriver {

    private final HttpTransport http;

    public HttpSmsDriver(final HttpTransport http) {
        this.http = http;
    }

    @Override
    public String driver() {
        return "HTTP";
    }

    @Override
    public void send(final ResolvedProviderDto provider, final String to, final String message) {
        final Map<String, String> config = provider.config() == null ? Map.of() : provider.config();
        final String url = config.get("url");
        if (url == null || url.isBlank()) {
            throw new IllegalStateException("HTTP SMS provider is missing url");
        }
        final String template = config.getOrDefault("bodyTemplate", "{\"to\":\"{{to}}\",\"message\":\"{{message}}\"}");
        final String body = TemplateRenderer.render(template, Map.of("to", to, "message", message));
        final Map<String, String> headers = new LinkedHashMap<>();
        headers.put("Content-Type", config.getOrDefault("contentType", "application/json"));
        if (provider.secret() != null && !provider.secret().isBlank()) {
            final String scheme = config.getOrDefault("authScheme", "Bearer ");
            headers.put(config.getOrDefault("authHeader", "Authorization"), scheme + provider.secret());
        }
        final int status = http.post(url, headers, body);
        if (status >= 300) {
            throw new IllegalStateException("HTTP SMS gateway rejected the message (HTTP " + status + ")");
        }
    }
}
