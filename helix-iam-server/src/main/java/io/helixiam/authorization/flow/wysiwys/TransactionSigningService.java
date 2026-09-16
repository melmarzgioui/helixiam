/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.flow.wysiwys;

import io.helixiam.authorization.flow.authenticators.CredentialVerifier;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;
import java.util.function.LongSupplier;
import java.util.function.Supplier;

/**
 * Helix IAM E4.4: WYSIWYS step-up / transaction signing (PSD2-SCA, "dynamic linking"). {@link #create}
 * builds a canonical, length-prefixed challenge from the transaction fields + a single-use nonce +
 * expiry and stores it; the phone shows exactly those fields and signs the canonical bytes with its
 * device key. {@link #sign} verifies that signature over the EXACT canonical bytes via the device
 * {@link CredentialVerifier} (type "device", reusing E4.1) — <b>bound to the transaction's stored
 * user</b>, never request input (the E4.3 IDOR lesson) — and consumes the nonce on success.
 */
public class TransactionSigningService {

    private final TransactionSigningStore store;
    private final CredentialVerifier credentialVerifier;
    private final Supplier<String> tokenGenerator;
    private final LongSupplier clock;
    private final long ttlMillis;

    public TransactionSigningService(final TransactionSigningStore store, final CredentialVerifier credentialVerifier,
                                     final Supplier<String> tokenGenerator, final LongSupplier clock,
                                     final long ttlMillis) {
        this.store = store;
        this.credentialVerifier = credentialVerifier;
        this.tokenGenerator = tokenGenerator;
        this.clock = clock;
        this.ttlMillis = ttlMillis;
    }

    /** Mints + stores a transaction-signing request; returns it so the RP can display + relay the challenge. */
    public SignedTransaction create(final String userId, final String action, final Map<String, String> params) {
        final String id = tokenGenerator.get();
        final String nonce = tokenGenerator.get();
        final long expiry = clock.getAsLong() + ttlMillis;
        final String canonical = WysiwysCanonicalizer.canonicalize(action, params, nonce, expiry);
        final SignedTransaction transaction =
                new SignedTransaction(id, userId, action, canonical, nonce, clock.getAsLong(), expiry);
        store.save(transaction);
        return transaction;
    }

    /**
     * Records the phone's signature: verify it over the exact canonical bytes (ES256, device
     * Credential SPI, bound to the stored user), then move the request to SIGNED if still valid.
     */
    public boolean sign(final String id, final String deviceId, final String signatureB64Url) {
        final SignedTransaction transaction = store.find(id).orElse(null);
        if (transaction == null) {
            return false;
        }
        final String challenge = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(transaction.canonicalChallenge().getBytes(StandardCharsets.UTF_8));
        final String input = json("deviceId", deviceId, "challenge", challenge, "signature", signatureB64Url);
        // Bind to the transaction's stored user — never a client-supplied id (auth bypass / IDOR).
        if (!credentialVerifier.verify("device", transaction.userId(), input)) {
            return false;
        }
        final boolean signed = transaction.sign(clock.getAsLong());
        store.save(transaction);
        return signed;
    }

    /** Single-use consume by the RP; returns the authorizing user id or null. */
    public String consume(final String id) {
        final SignedTransaction transaction = store.find(id).orElse(null);
        if (transaction == null) {
            return null;
        }
        final String userId = transaction.consume();
        if (userId != null) {
            store.save(transaction);
        }
        return userId;
    }

    /** Current status for the poll stream; UNKNOWN if the id is not (or no longer) present. */
    public String status(final String id) {
        return store.find(id).map(t -> t.status().name()).orElse("UNKNOWN");
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
