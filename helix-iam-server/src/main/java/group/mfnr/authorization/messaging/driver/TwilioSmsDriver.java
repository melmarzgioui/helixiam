package group.mfnr.authorization.messaging.driver;

import group.mfnr.authorization.amqp.messaging.ResolvedProviderDto;
import org.springframework.stereotype.Component;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Helix IAM notifications (N3): Twilio SMS driver. POSTs a form-encoded message to the Twilio Messages API
 * with HTTP Basic auth (Account SID : Auth Token). {@code config.accountSid} + {@code provider.fromAddress}
 * are the SID and From number; {@code secret} is the Auth Token.
 */
@Component
public class TwilioSmsDriver implements SmsDriver {

    static final String API = "https://api.twilio.com/2010-04-01/Accounts/%s/Messages.json";

    private final HttpTransport http;

    public TwilioSmsDriver(final HttpTransport http) {
        this.http = http;
    }

    @Override
    public String driver() {
        return "TWILIO";
    }

    @Override
    public void send(final ResolvedProviderDto provider, final String to, final String message) {
        final Map<String, String> config = provider.config() == null ? Map.of() : provider.config();
        final String accountSid = config.get("accountSid");
        if (accountSid == null || accountSid.isBlank()) {
            throw new IllegalStateException("Twilio SMS provider is missing accountSid");
        }
        final String url = String.format(API, URLEncoder.encode(accountSid, StandardCharsets.UTF_8));
        final String body = form(Map.of("To", to, "From", str(provider.fromAddress()), "Body", message));
        final String basic = Base64.getEncoder()
                .encodeToString((accountSid + ":" + str(provider.secret())).getBytes(StandardCharsets.UTF_8));
        final Map<String, String> headers = new LinkedHashMap<>();
        headers.put("Authorization", "Basic " + basic);
        headers.put("Content-Type", "application/x-www-form-urlencoded");
        final int status = http.post(url, headers, body);
        if (status >= 300) {
            throw new IllegalStateException("Twilio rejected the SMS (HTTP " + status + ")");
        }
    }

    private static String form(final Map<String, String> fields) {
        final StringBuilder b = new StringBuilder();
        fields.forEach((k, v) -> {
            if (b.length() > 0) {
                b.append('&');
            }
            b.append(URLEncoder.encode(k, StandardCharsets.UTF_8)).append('=')
                    .append(URLEncoder.encode(v == null ? "" : v, StandardCharsets.UTF_8));
        });
        return b.toString();
    }

    private static String str(final String s) {
        return s == null ? "" : s;
    }
}
