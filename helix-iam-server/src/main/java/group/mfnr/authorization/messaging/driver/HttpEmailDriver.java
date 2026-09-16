package group.mfnr.authorization.messaging.driver;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import group.mfnr.authorization.amqp.messaging.ResolvedProviderDto;
import org.springframework.stereotype.Component;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Helix IAM notifications (N3): a generic HTTP email-API driver (SendGrid / SES-style) for setups that block
 * SMTP. {@code config.url} is the endpoint; the JSON body carries {@code from/to/subject/body}; {@code secret}
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
