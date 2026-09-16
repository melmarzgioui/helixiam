/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.messaging.driver;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import io.helixiam.authorization.amqp.messaging.ResolvedProviderDto;
import org.springframework.stereotype.Component;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Helix IAM notifications (N6c): the Firebase Cloud Messaging (HTTP v1) push driver. Mints an RS256 JWT from
 * the realm's service-account JSON (provider {@code secret}), exchanges it at Google's OAuth token endpoint
 * for a short-lived bearer, then POSTs a {@code notification} message to each device token. The network goes
 * through {@link HttpTransport} so the driver is unit-testable without real Firebase credentials.
 */
@Component
public class FcmPushDriver implements PushDriver {

    private static final String SCOPE = "https://www.googleapis.com/auth/firebase.messaging";
    private static final String DEFAULT_TOKEN_URI = "https://oauth2.googleapis.com/token";

    private final HttpTransport http;
    private final ObjectMapper objectMapper = new ObjectMapper();

    public FcmPushDriver(final HttpTransport http) {
        this.http = http;
    }

    @Override
    public String driver() {
        return "FCM";
    }

    @Override
    public void send(final ResolvedProviderDto provider, final List<String> tokens, final String title,
                     final String body, final Map<String, String> data) {
        if (tokens == null || tokens.isEmpty()) {
            return;
        }
        final JsonNode sa = serviceAccount(provider.secret());
        final String tokenUri = sa.path("token_uri").asText(DEFAULT_TOKEN_URI);
        final String projectId = firstNonBlank(config(provider).get("projectId"), sa.path("project_id").asText(null));
        if (projectId == null || projectId.isBlank()) {
            throw new IllegalStateException("FCM provider is missing the project id");
        }
        final String bearer = exchangeForAccessToken(sa, tokenUri);
        final String fcmHost = config(provider).getOrDefault("host", "https://fcm.googleapis.com");
        final String sendUrl = fcmHost + "/v1/projects/" + projectId + "/messages:send";
        final Map<String, String> headers = new LinkedHashMap<>();
        headers.put("Authorization", "Bearer " + bearer);
        headers.put("Content-Type", "application/json");
        for (final String token : tokens) {
            final int status = http.post(sendUrl, headers, messagePayload(token, title, body, data));
            if (status >= 300) {
                throw new IllegalStateException("FCM rejected the message (HTTP " + status + ")");
            }
        }
    }

    private String exchangeForAccessToken(final JsonNode sa, final String tokenUri) {
        final String assertion = signedJwt(sa, tokenUri);
        final String form = "grant_type=" + URLEncoder.encode("urn:ietf:params:oauth:grant-type:jwt-bearer", StandardCharsets.UTF_8)
                + "&assertion=" + URLEncoder.encode(assertion, StandardCharsets.UTF_8);
        final HttpTransport.Response resp = http.postForResponse(tokenUri,
                Map.of("Content-Type", "application/x-www-form-urlencoded"), form);
        if (resp.status() >= 300) {
            throw new IllegalStateException("FCM token exchange failed (HTTP " + resp.status() + ")");
        }
        try {
            final String accessToken = objectMapper.readTree(resp.body()).path("access_token").asText(null);
            if (accessToken == null || accessToken.isBlank()) {
                throw new IllegalStateException("FCM token exchange returned no access_token");
            }
            return accessToken;
        } catch (final Exception e) {
            throw new IllegalStateException("FCM token exchange response was not JSON: " + e.getMessage(), e);
        }
    }

    private String signedJwt(final JsonNode sa, final String tokenUri) {
        try {
            final RSAPrivateKey key = rsaPrivateKey(sa.path("private_key").asText());
            final Instant now = Instant.now();
            final JWTClaimsSet claims = new JWTClaimsSet.Builder()
                    .issuer(sa.path("client_email").asText())
                    .audience(tokenUri)
                    .claim("scope", SCOPE)
                    .issueTime(Date.from(now))
                    .expirationTime(Date.from(now.plusSeconds(3600)))
                    .build();
            final SignedJWT jwt = new SignedJWT(new JWSHeader(JWSAlgorithm.RS256), claims);
            jwt.sign(new RSASSASigner(key));
            return jwt.serialize();
        } catch (final Exception e) {
            throw new IllegalStateException("Could not sign FCM service-account JWT: " + e.getMessage(), e);
        }
    }

    private String messagePayload(final String token, final String title, final String body, final Map<String, String> data) {
        final ObjectNode root = objectMapper.createObjectNode();
        final ObjectNode message = root.putObject("message");
        message.put("token", token);
        final ObjectNode notification = message.putObject("notification");
        notification.put("title", title == null ? "" : title);
        notification.put("body", body == null ? "" : body);
        if (data != null && !data.isEmpty()) {
            final ObjectNode dataNode = message.putObject("data");
            data.forEach(dataNode::put);
        }
        try {
            return objectMapper.writeValueAsString(root);
        } catch (final Exception e) {
            throw new IllegalStateException("Could not build FCM payload: " + e.getMessage(), e);
        }
    }

    private JsonNode serviceAccount(final String secret) {
        if (secret == null || secret.isBlank()) {
            throw new IllegalStateException("FCM provider is missing the service-account JSON secret");
        }
        try {
            return objectMapper.readTree(secret);
        } catch (final Exception e) {
            throw new IllegalStateException("FCM service-account secret is not valid JSON: " + e.getMessage(), e);
        }
    }

    private static RSAPrivateKey rsaPrivateKey(final String pem) throws Exception {
        final byte[] der = Base64.getMimeDecoder().decode(pem
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s", ""));
        return (RSAPrivateKey) KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(der));
    }

    private static Map<String, String> config(final ResolvedProviderDto provider) {
        return provider.config() == null ? Map.of() : provider.config();
    }

    private static String firstNonBlank(final String a, final String b) {
        return a != null && !a.isBlank() ? a : b;
    }
}
