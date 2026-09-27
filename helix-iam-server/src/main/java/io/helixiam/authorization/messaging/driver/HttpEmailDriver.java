/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.messaging.driver;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.helixiam.authorization.amqp.messaging.ResolvedProviderDto;
import io.helixiam.authorization.messaging.email.DeliveryResult;
import io.helixiam.authorization.messaging.email.DeliveryResult.Reason;
import io.helixiam.authorization.messaging.email.EmailMessage;
import io.helixiam.authorization.messaging.email.EmailTransport;
import io.helixiam.common.net.SsrfBlockedException;
import org.springframework.stereotype.Component;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * The generic HTTP email driver, for custom relays: it posts one fixed JSON shape
 * {@code {from, fromName, to, subject, body, html, contentType, text}} to {@code config.url}. {@code text} is the
 * plain-text part (for an HTML email, its text alternative with every link). The secret is sent as the
 * {@code Authorization} header value (default {@code Bearer }-prefixed; overridable with {@code config.authHeader} /
 * {@code config.authScheme}). The provider drivers (SMTP, CLOUDFLARE) are preferred where they fit.
 *
 * <p>Classification: 2xx is accepted; 401/403 (credentials), 408, 429 and 5xx are transient; any other status is a
 * permanent rejection. A URL the egress guard refuses is a configuration failure.
 */
@Component
public class HttpEmailDriver implements EmailTransport {

    public static final String DRIVER = "HTTP";

    private final HttpTransport http;
    private final ObjectMapper objectMapper = new ObjectMapper();

    public HttpEmailDriver(final HttpTransport http) {
        this.http = http;
    }

    @Override
    public String driver() {
        return DRIVER;
    }

    @Override
    public DeliveryResult deliver(final ResolvedProviderDto provider, final EmailMessage message) {
        final Map<String, String> config = provider.config() == null ? Map.of() : provider.config();
        final String url = config.get("url");
        if (url == null || url.isBlank()) {
            return DeliveryResult.permanent(Reason.CONFIGURATION, "The HTTP email provider has no url");
        }
        final ObjectNode json = objectMapper.createObjectNode();
        json.put("from", message.from() != null ? message.from().address() : provider.fromAddress());
        json.put("fromName", message.from() != null ? message.from().name() : provider.fromName());
        json.put("to", message.primaryRecipient().address());
        json.put("subject", message.subject());
        json.put("body", message.isHtml() ? message.html() : message.text());
        // Content type signal for the API: html=true means the body is text/html (an "html" field is also set so
        // SendGrid/SES-style APIs that key off a dedicated HTML field pick it up directly).
        json.put("html", message.isHtml());
        json.put("contentType", message.isHtml() ? "text/html" : "text/plain");
        json.put("text", message.text());
        final String payload;
        try {
            payload = objectMapper.writeValueAsString(json);
        } catch (final Exception e) {
            return DeliveryResult.permanent(Reason.MESSAGE_REJECTED, "The email could not be encoded");
        }
        final Map<String, String> headers = new LinkedHashMap<>();
        headers.put("Content-Type", "application/json");
        if (provider.secret() != null && !provider.secret().isBlank()) {
            headers.put(config.getOrDefault("authHeader", "Authorization"),
                    config.getOrDefault("authScheme", "Bearer ") + provider.secret());
        }
        final int status;
        try {
            status = http.post(url, headers, payload);
        } catch (final SsrfBlockedException e) {
            return DeliveryResult.permanent(Reason.CONFIGURATION, "The email API URL is not allowed by the egress policy");
        } catch (final RuntimeException e) {
            return e.getCause() instanceof SsrfBlockedException
                    ? DeliveryResult.permanent(Reason.CONFIGURATION, "The email API URL is not allowed by the egress policy")
                    : DeliveryResult.transientFailure(Reason.NETWORK, "Could not reach the email API");
        }
        return classify(status);
    }

    static DeliveryResult classify(final int status) {
        final String diagnostic = "HTTP " + status;
        if (status >= 200 && status < 300) {
            return DeliveryResult.accepted(null, diagnostic);
        }
        if (status == 401 || status == 403) {
            return DeliveryResult.transientFailure(Reason.AUTHENTICATION, diagnostic + " (credentials refused)");
        }
        if (status == 429) {
            return DeliveryResult.transientFailure(Reason.RATE_LIMITED, diagnostic);
        }
        if (status == 408 || status >= 500) {
            return DeliveryResult.transientFailure(Reason.PROVIDER_ERROR, diagnostic);
        }
        return DeliveryResult.permanent(Reason.MESSAGE_REJECTED, diagnostic);
    }
}
