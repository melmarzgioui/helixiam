/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.flow.qr;

import io.helixiam.authorization.flow.authenticators.CredentialVerifier;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Optional;
import java.util.function.LongSupplier;
import java.util.function.Supplier;

/**
 * Helix IAM E4.2: orchestrates the cross-device QR-login lifecycle. The browser {@link #open}s a
 * session (random id + rotating token); the QR shows {@code helix://qr-login/{id}?t={token}}. The
 * enrolled phone {@link #confirm}s by signing the current token with its device key — verified
 * through the generic device {@link CredentialVerifier} (type {@code "device"}, ES256 over the exact
 * token bytes, reusing E4.1). The browser then {@link #consume}s the CONFIRMED session exactly once.
 * Token rotation/expiry is enforced by {@link QrSession}; clock + token generation are injected.
 */
public class QrLoginService {

    private final QrSessionStore store;
    private final CredentialVerifier credentialVerifier;
    private final Supplier<String> tokenGenerator;
    private final LongSupplier clock;
    private final long ttlMillis;
    private final long rotationMillis;

    public QrLoginService(final QrSessionStore store, final CredentialVerifier credentialVerifier,
                          final Supplier<String> tokenGenerator, final LongSupplier clock,
                          final long ttlMillis, final long rotationMillis) {
        this.store = store;
        this.credentialVerifier = credentialVerifier;
        this.tokenGenerator = tokenGenerator;
        this.clock = clock;
        this.ttlMillis = ttlMillis;
        this.rotationMillis = rotationMillis;
    }

    /** Opens a new PENDING session and stores it; returns it so the caller can render the QR. */
    public QrSession open() {
        final String id = tokenGenerator.get();
        final String token = tokenGenerator.get();
        final QrSession session = new QrSession(id, clock.getAsLong(), ttlMillis, rotationMillis, token);
        store.save(session);
        return session;
    }

    /** Rotates the token if the interval elapsed, so the browser/QR always shows a fresh one. */
    public Optional<QrSession> refresh(final String id) {
        final Optional<QrSession> found = store.find(id);
        found.ifPresent(session -> {
            if (session.status() == QrSession.Status.PENDING && session.needsRotation(clock.getAsLong())) {
                session.rotate(tokenGenerator.get(), clock.getAsLong());
                store.save(session);
            }
        });
        return found;
    }

    /**
     * Phone confirmation: verify the device signature over the presented token (ES256, via the
     * device Credential SPI), then flip the session to CONFIRMED if the token is current + fresh.
     */
    public boolean confirm(final String id, final String token, final String userId,
                           final String deviceId, final String signatureB64Url) {
        final QrSession session = store.find(id).orElse(null);
        if (session == null) {
            return false;
        }
        final String challenge = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(token.getBytes(StandardCharsets.UTF_8));
        final String input = json("deviceId", deviceId, "challenge", challenge, "signature", signatureB64Url);
        if (!credentialVerifier.verify("device", userId, input)) {
            return false;
        }
        final boolean confirmed = session.confirm(userId, token, clock.getAsLong());
        if (confirmed) {
            store.save(session);
        }
        return confirmed;
    }

    /** Single-use consume by the initiating browser; returns the bound user id or null. */
    public String consume(final String id) {
        final QrSession session = store.find(id).orElse(null);
        if (session == null) {
            return null;
        }
        final String userId = session.consume();
        if (userId != null) {
            store.save(session);
        }
        return userId;
    }

    /** Current status for the SSE/poll stream; UNKNOWN if the session id is not (or no longer) present. */
    public String status(final String id) {
        return store.find(id).map(s -> s.status().name()).orElse("UNKNOWN");
    }

    private static String json(final String... kv) {
        final StringBuilder sb = new StringBuilder("{");
        for (int i = 0; i < kv.length; i += 2) {
            if (i > 0) {
                sb.append(',');
            }
            sb.append('"').append(kv[i]).append("\":\"").append(escape(kv[i + 1])).append('"');
        }
        return sb.append('}').toString();
    }

    private static String escape(final String value) {
        return value == null ? "" : value.replace("\\", "\\\\").replace("\"", "\\\"");
    }
}
