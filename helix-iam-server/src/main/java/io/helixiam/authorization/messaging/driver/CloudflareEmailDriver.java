/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.messaging.driver;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.helixiam.authorization.amqp.messaging.ResolvedProviderDto;
import io.helixiam.authorization.messaging.email.DeliveryResult;
import io.helixiam.authorization.messaging.email.DeliveryResult.Reason;
import io.helixiam.authorization.messaging.email.EmailAddress;
import io.helixiam.authorization.messaging.email.EmailMessage;
import io.helixiam.authorization.messaging.email.EmailTransport;
import io.helixiam.authorization.messaging.email.TlsTrust;
import io.helixiam.common.net.OutboundUrlGuard;
import io.helixiam.common.net.SsrfBlockedException;
import io.helixiam.common.startup.DeploymentProfile;
import org.springframework.stereotype.Component;

import javax.net.ssl.SSLException;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpTimeoutException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

/**
 * The Cloudflare Email Service driver ({@code CLOUDFLARE}): sends over HTTPS, so it works where outbound SMTP ports
 * (25, 465, 587) are blocked.
 *
 * <p>{@code POST {baseUrl}/accounts/{accountId}/email/sending/send} with {@code Authorization: Bearer <apiToken>} and
 * the JSON body {@code {from: {address, name}, to: [{address, name}], reply_to: {address, name}, subject, html, text}}
 * ({@code name} and {@code reply_to} optional; the field is {@code address}, never {@code email}).
 *
 * <p>Settings ({@code provider.config()}): {@code accountId} (required), {@code baseUrl} (default
 * {@value #DEFAULT_BASE_URL}; {@code https} unless the server runs with the {@code dev} profile),
 * {@code connectTimeoutMs} (default 5000), {@code readTimeoutMs} (default 15000) and {@code caBundle} (PEM
 * certificates trusted in addition to the JDK roots, for a TLS-inspecting proxy). The secret is the API token (needs
 * Account → Email Sending → Edit); it is never logged or echoed in a diagnostic.
 *
 * <p>Classification: a 2xx with {@code success: true} is {@code ACCEPTED} (recipient in {@code delivered}),
 * {@code QUEUED} (in {@code queued}) or {@code PERMANENT_FAILURE} (in {@code permanent_bounces}); 400 and 413 are
 * permanent; 401 and 403 (bad token, sending domain not onboarded) are transient, the operator must fix them; 408,
 * 429 and 5xx are transient; network errors and timeouts are transient. At most {@value #MAX_RESPONSE_BYTES} bytes of
 * the response are read. The diagnostic is the HTTP status and the first error's code and message.
 *
 * <p>Every request passes the egress guard ({@link OutboundUrlGuard}). Redirects are not followed.
 */
@Component
public class CloudflareEmailDriver implements EmailTransport {

    public static final String DRIVER = "CLOUDFLARE";
    public static final String DEFAULT_BASE_URL = "https://api.cloudflare.com/client/v4";
    public static final int MAX_RESPONSE_BYTES = 1_048_576;
    static final int DEFAULT_CONNECT_TIMEOUT_MS = 5_000;
    static final int DEFAULT_READ_TIMEOUT_MS = 15_000;

    private static final ObjectMapper JSON = new ObjectMapper();
    private static final int MAX_CLIENTS = 32;

    private final OutboundUrlGuard egressGuard;
    private final DeploymentProfile profile;
    private final Map<String, HttpClient> clients = new ConcurrentHashMap<>();

    public CloudflareEmailDriver(final OutboundUrlGuard egressGuard, final DeploymentProfile profile) {
        this.egressGuard = egressGuard;
        this.profile = profile == null ? DeploymentProfile.production() : profile;
    }

    @Override
    public String driver() {
        return DRIVER;
    }

    @Override
    public DeliveryResult deliver(final ResolvedProviderDto provider, final EmailMessage input) {
        final Settings settings;
        try {
            settings = Settings.of(provider.config() == null ? Map.of() : provider.config(), profile.isDev());
        } catch (final IllegalArgumentException e) {
            return DeliveryResult.permanent(Reason.CONFIGURATION, "Cloudflare settings: " + e.getMessage());
        }
        final String token = provider.secret() == null ? "" : provider.secret().trim();
        if (token.isEmpty()) {
            return DeliveryResult.permanent(Reason.CONFIGURATION, "The Cloudflare provider has no API token");
        }
        final EmailMessage message = input.withDefaultFrom(provider.fromAddress(), provider.fromName());
        if (message.from() == null) {
            return DeliveryResult.permanent(Reason.CONFIGURATION, "The email provider has no from address");
        }
        final String url = settings.sendUrl();
        try {
            egressGuard.checkAllowed(url);
        } catch (final SsrfBlockedException e) {
            return DeliveryResult.permanent(Reason.CONFIGURATION, "The Cloudflare API URL is not allowed by the egress policy");
        }
        final String body;
        try {
            body = JSON.writeValueAsString(requestBody(message));
        } catch (final IOException e) {
            return DeliveryResult.permanent(Reason.MESSAGE_REJECTED, "The email could not be encoded");
        }
        final HttpRequest request = HttpRequest.newBuilder(URI.create(url))
                .timeout(Duration.ofMillis(settings.readTimeoutMs()))
                .header("Authorization", "Bearer " + token)
                .header("Content-Type", "application/json")
                .header("Accept", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(body, StandardCharsets.UTF_8))
                .build();
        final int status;
        final byte[] response;
        final boolean truncated;
        try {
            final HttpResponse<InputStream> res = client(settings).send(request, HttpResponse.BodyHandlers.ofInputStream());
            status = res.statusCode();
            try (InputStream in = res.body()) {
                final byte[] read = in.readNBytes(MAX_RESPONSE_BYTES + 1);
                truncated = read.length > MAX_RESPONSE_BYTES;
                response = truncated ? new byte[0] : read;
            }
        } catch (final HttpTimeoutException e) {
            return DeliveryResult.transientFailure(Reason.NETWORK, "The Cloudflare API timed out");
        } catch (final SSLException e) {
            return DeliveryResult.transientFailure(Reason.NETWORK,
                    "TLS handshake with the Cloudflare API failed (certificate or protocol)");
        } catch (final IOException e) {
            return DeliveryResult.transientFailure(Reason.NETWORK, "Could not reach the Cloudflare API");
        } catch (final InterruptedException e) {
            Thread.currentThread().interrupt();
            return DeliveryResult.transientFailure(Reason.NETWORK, "Interrupted while calling the Cloudflare API");
        }
        return scrub(classify(status, response, truncated, message), token);
    }

    /** The request body: {@code address} (never {@code email}), optional names and reply-to, html and text. */
    static ObjectNode requestBody(final EmailMessage message) {
        final ObjectNode json = JSON.createObjectNode();
        json.set("from", mailbox(message.from()));
        final ArrayNode to = json.putArray("to");
        message.to().forEach(a -> to.add(mailbox(a)));
        if (message.replyTo() != null) {
            json.set("reply_to", mailbox(message.replyTo()));
        }
        json.put("subject", message.subject());
        if (message.isHtml()) {
            json.put("html", message.html());
        }
        json.put("text", message.text());
        return json;
    }

    private static ObjectNode mailbox(final EmailAddress a) {
        final ObjectNode node = JSON.createObjectNode();
        node.put("address", a.address());
        if (a.name() != null) {
            node.put("name", a.name());
        }
        return node;
    }

    /** Classifies a Cloudflare response (the table in the class javadoc). */
    static DeliveryResult classify(final int status, final byte[] body, final boolean truncated,
                                   final EmailMessage message) {
        final JsonNode json = parse(body);
        final String diagnostic = "HTTP " + status + firstError(json) + (truncated ? " (response over 1 MiB ignored)" : "");
        if (status >= 200 && status < 300) {
            if (json == null) {
                return DeliveryResult.accepted(null, diagnostic);
            }
            if (!json.path("success").asBoolean(false)) {
                return DeliveryResult.permanent(Reason.PROVIDER_ERROR, diagnostic + " (success: false)");
            }
            final JsonNode result = json.path("result");
            final Set<String> recipients = message.to().stream().map(a -> a.address().toLowerCase(Locale.ROOT))
                    .collect(Collectors.toSet());
            final List<String> bounced = matching(result.path("permanent_bounces"), recipients);
            final String providerId = text(result, "message_id", "id");
            if (!bounced.isEmpty()) {
                return DeliveryResult.bounced(bounced, diagnostic + " (permanent bounce)");
            }
            if (!matching(result.path("queued"), recipients).isEmpty()) {
                return DeliveryResult.queued(providerId, diagnostic + " (queued)");
            }
            return DeliveryResult.accepted(providerId, diagnostic + " (delivered)");
        }
        if (status == 400 || status == 413) {
            return DeliveryResult.permanent(Reason.MESSAGE_REJECTED, diagnostic);
        }
        if (status == 401 || status == 403) {
            return DeliveryResult.transientFailure(Reason.AUTHENTICATION,
                    diagnostic + " (check the API token and that the sending domain is onboarded)");
        }
        if (status == 429) {
            return DeliveryResult.transientFailure(Reason.RATE_LIMITED, diagnostic);
        }
        if (status == 408 || status >= 500) {
            return DeliveryResult.transientFailure(Reason.PROVIDER_ERROR, diagnostic);
        }
        if (status == 404 || status < 400) { // not found (account id, base URL) or an unexpected 1xx/3xx
            return DeliveryResult.permanent(Reason.CONFIGURATION, diagnostic + " (check accountId and baseUrl)");
        }
        return DeliveryResult.permanent(Reason.MESSAGE_REJECTED, diagnostic);
    }

    private static JsonNode parse(final byte[] body) {
        if (body == null || body.length == 0) {
            return null;
        }
        try {
            final JsonNode node = JSON.readTree(body);
            return node != null && node.isObject() ? node : null;
        } catch (final IOException e) {
            return null;
        }
    }

    /** {@code ": <code> <message>"} of the first error, or empty. */
    private static String firstError(final JsonNode json) {
        if (json == null) {
            return "";
        }
        final JsonNode first = json.path("errors").path(0);
        if (first.isMissingNode() || first.isNull()) {
            return "";
        }
        final String code = first.path("code").asText("");
        final String msg = first.path("message").asText("");
        final String joined = (code + " " + msg).trim();
        return joined.isEmpty() ? "" : ": " + (joined.length() > 200 ? joined.substring(0, 200) + "…" : joined);
    }

    private static List<String> matching(final JsonNode list, final Set<String> recipients) {
        final List<String> out = new ArrayList<>();
        if (list.isArray()) {
            list.forEach(n -> {
                final String v = n.isTextual() ? n.asText() : n.path("address").asText("");
                if (recipients.contains(v.toLowerCase(Locale.ROOT))) {
                    out.add(v);
                }
            });
        }
        return out;
    }

    private static String text(final JsonNode node, final String... fields) {
        for (final String f : fields) {
            final JsonNode v = node.path(f);
            if (v.isTextual() && !v.asText().isBlank()) {
                return v.asText();
            }
        }
        return null;
    }

    /** Never let the token reach a diagnostic, even if the API echoed it. */
    private static DeliveryResult scrub(final DeliveryResult r, final String token) {
        if (r.diagnostic() == null || token.length() < 4 || !r.diagnostic().contains(token)) {
            return r;
        }
        return new DeliveryResult(r.status(), r.reason(), r.providerMessageId(), r.diagnostic().replace(token, "***"),
                r.bouncedRecipients());
    }

    private HttpClient client(final Settings settings) {
        final String key = settings.connectTimeoutMs() + "|" + (settings.caBundle() == null ? "" : settings.caBundle());
        if (clients.size() >= MAX_CLIENTS && !clients.containsKey(key)) {
            clients.clear();
        }
        return clients.computeIfAbsent(key, k -> HttpClient.newBuilder()
                .connectTimeout(Duration.ofMillis(settings.connectTimeoutMs()))
                .followRedirects(HttpClient.Redirect.NEVER)
                .sslContext(TlsTrust.context(settings.caBundle()))
                .build());
    }

    /** The parsed, validated settings of a Cloudflare provider. */
    public record Settings(String accountId, String baseUrl, int connectTimeoutMs, int readTimeoutMs, String caBundle) {

        /**
         * Parses the provider config; {@code dev} allows an {@code http://} base URL.
         *
         * @throws IllegalArgumentException naming the first invalid setting
         */
        public static Settings of(final Map<String, String> config, final boolean dev) {
            final String accountId = blankToNull(config.get("accountId"));
            if (accountId == null) {
                throw new IllegalArgumentException("accountId is required");
            }
            if (!accountId.matches("[A-Za-z0-9_-]{1,64}")) {
                throw new IllegalArgumentException("accountId must be letters, digits, '-' or '_'");
            }
            final String baseUrl = baseUrl(blankToNull(config.get("baseUrl")), dev);
            final int connect = intSetting(config, "connectTimeoutMs", DEFAULT_CONNECT_TIMEOUT_MS);
            final int read = intSetting(config, "readTimeoutMs", DEFAULT_READ_TIMEOUT_MS);
            final String caBundle = blankToNull(config.get("caBundle"));
            if (caBundle != null) {
                TlsTrust.parse(caBundle);
            }
            return new Settings(accountId, baseUrl, connect, read, caBundle);
        }

        /** {@code {baseUrl}/accounts/{accountId}/email/sending/send}. */
        public String sendUrl() {
            return baseUrl + "/accounts/" + URLEncoder.encode(accountId, StandardCharsets.UTF_8) + "/email/sending/send";
        }

        private static String baseUrl(final String raw, final boolean dev) {
            if (raw == null) {
                return DEFAULT_BASE_URL;
            }
            final URI uri;
            try {
                uri = new URI(raw);
            } catch (final java.net.URISyntaxException e) {
                throw new IllegalArgumentException("baseUrl is not a URL");
            }
            final String scheme = uri.getScheme() == null ? "" : uri.getScheme().toLowerCase(Locale.ROOT);
            if (uri.getHost() == null || uri.getRawUserInfo() != null || uri.getRawQuery() != null
                    || uri.getRawFragment() != null) {
                throw new IllegalArgumentException("baseUrl must be an absolute URL without credentials, query or fragment");
            }
            if (!"https".equals(scheme) && !(dev && "http".equals(scheme))) {
                throw new IllegalArgumentException("baseUrl must use https");
            }
            return raw.replaceAll("/+$", "");
        }

        private static int intSetting(final Map<String, String> config, final String key, final int dflt) {
            final String raw = blankToNull(config.get(key));
            if (raw == null) {
                return dflt;
            }
            final int v;
            try {
                v = Integer.parseInt(raw);
            } catch (final NumberFormatException e) {
                throw new IllegalArgumentException(key + " must be a number");
            }
            if (v < 100 || v > 300_000) {
                throw new IllegalArgumentException(key + " must be between 100 and 300000");
            }
            return v;
        }

        private static String blankToNull(final String v) {
            return v == null || v.isBlank() ? null : v.trim();
        }
    }
}
