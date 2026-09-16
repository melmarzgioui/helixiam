package group.mfnr.authorization.messaging.driver;

import com.fasterxml.jackson.databind.ObjectMapper;
import group.mfnr.authorization.amqp.messaging.ResolvedProviderDto;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Helix IAM notifications (N6c): the FCM + APNs push drivers mint real signed JWTs (FCM: RS256 service-account
 * → Google OAuth bearer; APNs: ES256 .p8) and POST a correctly-shaped push to the platform endpoint. Verified
 * against capturing transports, exactly like the HTTP SMS/email drivers (no real Google/Apple credentials).
 */
class PushDriverTest {

    private final ObjectMapper json = new ObjectMapper();

    private static String pem(final String type, final byte[] der) {
        return "-----BEGIN " + type + "-----\n"
                + Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(der)
                + "\n-----END " + type + "-----\n";
    }

    @Test
    void fcmDriver_exchangesServiceAccountJwtForBearer_thenPostsToFcmV1() throws Exception {
        final KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        final KeyPair kp = kpg.generateKeyPair();
        final String saJson = json.writeValueAsString(Map.of(
                "type", "service_account",
                "project_id", "test-proj",
                "private_key", pem("PRIVATE KEY", kp.getPrivate().getEncoded()),
                "client_email", "fcm@test-proj.iam.gserviceaccount.com",
                "token_uri", "https://oauth2.test/token"));

        final AtomicReference<String> tokenUrl = new AtomicReference<>();
        final AtomicReference<String> sendUrl = new AtomicReference<>();
        final AtomicReference<Map<String, String>> sendHeaders = new AtomicReference<>();
        final AtomicReference<String> sendBody = new AtomicReference<>();
        final HttpTransport transport = new HttpTransport() {
            @Override public int post(final String url, final Map<String, String> headers, final String body) {
                sendUrl.set(url); sendHeaders.set(headers); sendBody.set(body);
                return 200;
            }
            @Override public Response postForResponse(final String url, final Map<String, String> headers, final String body) {
                tokenUrl.set(url);
                return new Response(200, "{\"access_token\":\"ya29.test-bearer\",\"expires_in\":3600}");
            }
        };

        final ResolvedProviderDto provider = new ResolvedProviderDto("PUSH", "FCM", null, null,
                Map.of("projectId", "test-proj"), saJson);
        new FcmPushDriver(transport).send(provider, List.of("device-token-1"), "Approve sign-in",
                "Tap to approve. Match 42.", Map.of("approvalId", "a1"));

        assertThat(tokenUrl.get()).isEqualTo("https://oauth2.test/token");
        assertThat(sendUrl.get()).isEqualTo("https://fcm.googleapis.com/v1/projects/test-proj/messages:send");
        assertThat(sendHeaders.get()).containsEntry("Authorization", "Bearer ya29.test-bearer");
        assertThat(sendBody.get()).contains("device-token-1").contains("Approve sign-in").contains("Tap to approve");
    }

    @Test
    void apnsDriver_signsEs256Jwt_andPostsToApnsWithTopic() throws Exception {
        final KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(new ECGenParameterSpec("secp256r1"));
        final KeyPair kp = kpg.generateKeyPair();
        final String p8 = pem("PRIVATE KEY", kp.getPrivate().getEncoded());

        final AtomicReference<String> url = new AtomicReference<>();
        final AtomicReference<Map<String, String>> headers = new AtomicReference<>();
        final AtomicReference<String> body = new AtomicReference<>();
        final HttpTransport transport = (u, h, b) -> { url.set(u); headers.set(h); body.set(b); return 200; };

        final ResolvedProviderDto provider = new ResolvedProviderDto("PUSH", "APNS", null, null,
                Map.of("keyId", "KEY123", "teamId", "TEAM456", "bundleId", "com.example.app"), p8);
        new ApnsPushDriver(transport).send(provider, List.of("apns-device-token"), "Approve sign-in",
                "Tap to approve. Match 42.", Map.of("approvalId", "a1"));

        assertThat(url.get()).isEqualTo("https://api.push.apple.com/3/device/apns-device-token");
        assertThat(headers.get()).containsEntry("apns-topic", "com.example.app");
        assertThat(headers.get().get("authorization")).startsWith("bearer ");
        // The JWT header must declare ES256 + the key id.
        final String jwt = headers.get().get("authorization").substring("bearer ".length());
        final String jwtHeader = new String(Base64.getUrlDecoder().decode(jwt.split("\\.")[0]));
        assertThat(jwtHeader).contains("ES256").contains("KEY123");
        assertThat(body.get()).contains("Approve sign-in").contains("Tap to approve");
    }
}
