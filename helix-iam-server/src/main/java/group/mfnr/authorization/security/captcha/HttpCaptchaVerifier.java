package group.mfnr.authorization.security.captcha;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;

/**
 * Auth-hardening (feature 5): production {@link CaptchaVerifier} that POSTs the token to the provider's
 * siteverify endpoint (Turnstile or reCAPTCHA — same form contract: {@code secret} + {@code response}) and
 * parses the {@code "success": true} flag. Endpoint bases are configurable for tests. Fails CLOSED
 * (returns {@code false}) on network/parse error, since CAPTCHA is an explicit anti-abuse gate the operator
 * opted into.
 */
@Component
public class HttpCaptchaVerifier implements CaptchaVerifier {

    private static final Logger LOG = LogManager.getLogger(HttpCaptchaVerifier.class);

    private final String turnstileUrl;
    private final String recaptchaUrl;
    private final HttpClient client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(3)).build();

    public HttpCaptchaVerifier(
            @Value("${helix.captcha.turnstile-url:https://challenges.cloudflare.com/turnstile/v0/siteverify}") final String turnstileUrl,
            @Value("${helix.captcha.recaptcha-url:https://www.google.com/recaptcha/api/siteverify}") final String recaptchaUrl) {
        this.turnstileUrl = turnstileUrl;
        this.recaptchaUrl = recaptchaUrl;
    }

    @Override
    public boolean verify(final String provider, final String secretKey, final String token, final String remoteIp) {
        if (secretKey == null || secretKey.isBlank() || token == null || token.isBlank()) {
            return false;
        }
        final String endpoint = "recaptcha".equalsIgnoreCase(provider) ? recaptchaUrl : turnstileUrl;
        try {
            final StringBuilder body = new StringBuilder()
                    .append("secret=").append(enc(secretKey))
                    .append("&response=").append(enc(token));
            if (remoteIp != null && !remoteIp.isBlank()) {
                body.append("&remoteip=").append(enc(remoteIp));
            }
            final HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(endpoint))
                    .timeout(Duration.ofSeconds(3))
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .POST(HttpRequest.BodyPublishers.ofString(body.toString()))
                    .build();
            final HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
            // Cheap, dependency-free parse of the JSON success flag.
            return response.statusCode() == 200 && response.body() != null
                    && response.body().replaceAll("\\s", "").contains("\"success\":true");
        } catch (final Exception e) {
            LOG.warn("CAPTCHA verification failed ({}), denying: {}", provider, e.getMessage());
            return false;
        }
    }

    private static String enc(final String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }
}
