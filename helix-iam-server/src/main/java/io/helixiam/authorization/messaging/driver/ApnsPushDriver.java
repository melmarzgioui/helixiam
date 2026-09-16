package io.helixiam.authorization.messaging.driver;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import io.helixiam.authorization.amqp.messaging.ResolvedProviderDto;
import org.springframework.stereotype.Component;

import java.security.KeyFactory;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Helix IAM notifications (N6c): the Apple Push Notification service driver. Mints an ES256 JWT from the
 * realm's {@code .p8} auth key (provider {@code secret}) — {@code kid}=Key ID, {@code iss}=Team ID — and POSTs
 * an {@code aps} alert to each device token over HTTP/2 with the {@code apns-topic} (bundle id). The network
 * goes through {@link HttpTransport} so the driver is unit-testable without real Apple credentials.
 */
@Component
public class ApnsPushDriver implements PushDriver {

    /** Production APNs host. (Sandbox is api.sandbox.push.apple.com — overridable via config.host.) */
    private static final String PROD_HOST = "https://api.push.apple.com";

    private final HttpTransport http;
    private final ObjectMapper objectMapper = new ObjectMapper();

    public ApnsPushDriver(final HttpTransport http) {
        this.http = http;
    }

    @Override
    public String driver() {
        return "APNS";
    }

    @Override
    public void send(final ResolvedProviderDto provider, final List<String> tokens, final String title,
                     final String body, final Map<String, String> data) {
        if (tokens == null || tokens.isEmpty()) {
            return;
        }
        final Map<String, String> config = provider.config() == null ? Map.of() : provider.config();
        final String topic = config.get("bundleId");
        if (topic == null || topic.isBlank()) {
            throw new IllegalStateException("APNs provider is missing the bundle id (topic)");
        }
        final String host = config.getOrDefault("host", PROD_HOST);
        final String jwt = signedJwt(provider.secret(), config.get("keyId"), config.get("teamId"));
        final String payload = apsPayload(title, body, data);
        for (final String token : tokens) {
            final Map<String, String> headers = new LinkedHashMap<>();
            headers.put("authorization", "bearer " + jwt);
            headers.put("apns-topic", topic);
            headers.put("apns-push-type", "alert");
            headers.put("content-type", "application/json");
            final int status = http.post(host + "/3/device/" + token, headers, payload);
            if (status >= 300) {
                throw new IllegalStateException("APNs rejected the message (HTTP " + status + ")");
            }
        }
    }

    private String signedJwt(final String p8, final String keyId, final String teamId) {
        if (p8 == null || p8.isBlank()) {
            throw new IllegalStateException("APNs provider is missing the .p8 auth key secret");
        }
        if (keyId == null || keyId.isBlank() || teamId == null || teamId.isBlank()) {
            throw new IllegalStateException("APNs provider is missing the keyId/teamId");
        }
        try {
            final ECPrivateKey key = ecPrivateKey(p8);
            final Instant now = Instant.now();
            final JWTClaimsSet claims = new JWTClaimsSet.Builder()
                    .issuer(teamId)
                    .issueTime(Date.from(now))
                    .build();
            final SignedJWT jwt = new SignedJWT(
                    new JWSHeader.Builder(JWSAlgorithm.ES256).keyID(keyId).build(), claims);
            jwt.sign(new ECDSASigner(key));
            return jwt.serialize();
        } catch (final Exception e) {
            throw new IllegalStateException("Could not sign APNs JWT: " + e.getMessage(), e);
        }
    }

    private String apsPayload(final String title, final String body, final Map<String, String> data) {
        final ObjectNode root = objectMapper.createObjectNode();
        final ObjectNode aps = root.putObject("aps");
        final ObjectNode alert = aps.putObject("alert");
        alert.put("title", title == null ? "" : title);
        alert.put("body", body == null ? "" : body);
        if (data != null) {
            data.forEach(root::put);
        }
        try {
            return objectMapper.writeValueAsString(root);
        } catch (final Exception e) {
            throw new IllegalStateException("Could not build APNs payload: " + e.getMessage(), e);
        }
    }

    private static ECPrivateKey ecPrivateKey(final String p8) throws Exception {
        final byte[] der = Base64.getMimeDecoder().decode(p8
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s", ""));
        return (ECPrivateKey) KeyFactory.getInstance("EC").generatePrivate(new PKCS8EncodedKeySpec(der));
    }
}
