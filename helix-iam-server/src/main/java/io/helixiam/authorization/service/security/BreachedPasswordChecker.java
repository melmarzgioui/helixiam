package io.helixiam.authorization.service.security;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Duration;
import java.util.HexFormat;
import java.util.function.Function;

/**
 * Auth-hardening (feature 4): breached-password detection via the Have I Been Pwned range API using
 * k-anonymity. The password's SHA-1 is split into a 5-char prefix (sent to the API) and the remaining
 * suffix (matched locally against the returned hash list), so the full password hash never leaves the
 * server.
 *
 * <p><b>Fail-open:</b> any network/parse error returns {@code false} (not breached) so a HIBP outage never
 * blocks a password set/reset or a login. The API base is injectable so tests can stub the HTTP layer.
 */
@Component
public class BreachedPasswordChecker {

    private static final Logger LOG = LogManager.getLogger(BreachedPasswordChecker.class);
    static final String DEFAULT_BASE = "https://api.pwnedpasswords.com/range/";

    /** Fetches the suffix list for a 5-char SHA-1 prefix; returns the raw response body. */
    public interface RangeFetcher {
        String fetch(String prefix5);
    }

    private final RangeFetcher fetcher;

    /** Production wiring: a real HTTP fetcher against the configurable HIBP base URL. */
    @Autowired
    public BreachedPasswordChecker(@Value("${helix.hibp.base-url:" + DEFAULT_BASE + "}") final String baseUrl) {
        this(httpFetcher(baseUrl));
    }

    /** Test seam: inject a stub fetcher. */
    public BreachedPasswordChecker(final RangeFetcher fetcher) {
        this.fetcher = fetcher;
    }

    /**
     * @return {@code true} only when the password's SHA-1 suffix appears in the HIBP range list; {@code false}
     * when not found <em>or</em> on any error (fail-open).
     */
    public boolean isBreached(final String rawPassword) {
        if (rawPassword == null || rawPassword.isEmpty()) {
            return false;
        }
        final String sha1 = sha1Hex(rawPassword);
        final String prefix = sha1.substring(0, 5);
        final String suffix = sha1.substring(5);
        try {
            final String body = fetcher.fetch(prefix);
            if (body == null || body.isBlank()) {
                return false;
            }
            for (final String line : body.split("\\R")) {
                final int colon = line.indexOf(':');
                final String hashSuffix = colon >= 0 ? line.substring(0, colon) : line;
                if (hashSuffix.trim().equalsIgnoreCase(suffix)) {
                    return true;
                }
            }
            return false;
        } catch (final RuntimeException e) {
            LOG.warn("HIBP lookup failed, failing open (treating password as not breached): {}", e.getMessage());
            return false;
        }
    }

    private static String sha1Hex(final String value) {
        try {
            final MessageDigest md = MessageDigest.getInstance("SHA-1");
            final byte[] digest = md.digest(value.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(digest).toUpperCase();
        } catch (final Exception e) {
            throw new IllegalStateException("SHA-1 unavailable", e);
        }
    }

    private static RangeFetcher httpFetcher(final String baseUrl) {
        final String base = baseUrl.endsWith("/") ? baseUrl : baseUrl + "/";
        final HttpClient client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(3)).build();
        final Function<String, HttpRequest> request = prefix -> HttpRequest.newBuilder()
                .uri(URI.create(base + prefix))
                .timeout(Duration.ofSeconds(3))
                .header("Add-Padding", "true")
                .GET()
                .build();
        return prefix -> {
            try {
                final HttpResponse<String> response = client.send(request.apply(prefix), HttpResponse.BodyHandlers.ofString());
                return response.statusCode() == 200 ? response.body() : null;
            } catch (final Exception e) {
                throw new IllegalStateException(e);
            }
        };
    }
}
