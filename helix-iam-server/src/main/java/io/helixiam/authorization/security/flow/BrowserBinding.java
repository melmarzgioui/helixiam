/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.security.flow;

import jakarta.servlet.http.HttpSession;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * Binds a federated login to the browser that started it (EUDI wallet, spec §10.3; controller ruling 1). At login
 * start the broker keeps a random 128-bit secret in the HTTP session (per realm and provider alias) and hands the
 * provider only its hash, {@code base64url(SHA-256(secret))}. Every later step from that browser recomputes the hash
 * from the session: the federation callback, and the wallet page's cross-device code issue (Task 18).
 *
 * <p>The secret is a session attribute, not the session id: ids rotate (Task 2 calls {@code changeSessionId()}), the
 * attributes move with them. The secret never leaves the server; the hash is what wallet transactions store.
 */
public final class BrowserBinding {

    /** Session attribute holding the secret, followed by the realm and the provider alias ({@link #sessionKey}). */
    static final String ATTRIBUTE_PREFIX = "HELIX_FED_BINDING_";

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final int SECRET_BYTES = 16;

    private BrowserBinding() {
    }

    /**
     * The session attribute name of a per-login value: {@code prefix} followed by the realm and the provider alias.
     * Production readiness item 2: the broker's state, browser binding and wallet transaction are kept per (realm,
     * alias), so two realms that use the same alias (the console proposes {@code eudi-wallet} in every realm) can sign
     * in from one browser at the same time without clobbering each other. The realm is length-prefixed, so no realm
     * and alias pair can spell another pair's name; a {@code null} realm (outside a realm-routed request) is empty.
     */
    public static String sessionKey(final String prefix, final String realmId, final String alias) {
        final String realm = realmId == null ? "" : realmId;
        return prefix + realm.length() + ":" + realm + ":" + alias;
    }

    /** Starts a new binding for {@code alias} of {@code realmId} (replacing any earlier one) and returns its hash. */
    public static String begin(final HttpSession session, final String realmId, final String alias) {
        final byte[] bytes = new byte[SECRET_BYTES];
        RANDOM.nextBytes(bytes);
        final String secret = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
        session.setAttribute(sessionKey(ATTRIBUTE_PREFIX, realmId, alias), secret);
        return hash(secret);
    }

    /** The hash of this browser's binding for {@code alias} of {@code realmId}, or {@code null} when there is none. */
    public static String current(final HttpSession session, final String realmId, final String alias) {
        if (session == null) {
            return null;
        }
        return session.getAttribute(sessionKey(ATTRIBUTE_PREFIX, realmId, alias)) instanceof String secret
                ? hash(secret) : null;
    }

    /** Ends the binding for {@code alias} of {@code realmId} (after a successful login). */
    public static void clear(final HttpSession session, final String realmId, final String alias) {
        if (session != null) {
            session.removeAttribute(sessionKey(ATTRIBUTE_PREFIX, realmId, alias));
        }
    }

    private static String hash(final String secret) {
        try {
            return Base64.getUrlEncoder().withoutPadding().encodeToString(
                    MessageDigest.getInstance("SHA-256").digest(secret.getBytes(StandardCharsets.US_ASCII)));
        } catch (final NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is not available", e);
        }
    }
}
