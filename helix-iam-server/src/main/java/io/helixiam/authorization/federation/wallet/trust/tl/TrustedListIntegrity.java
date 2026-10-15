/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.wallet.trust.tl;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.Base64;

/**
 * HMAC-SHA256 over the stored rows that decide trust: a source's settings (URL, format, pinned signers, types,
 * statuses, territories) and the verified services of a source or member, keyed from {@code DB_ENCRYPTION}
 * ({@code database.encryption}). Someone who can write the database but does not hold that key cannot pin another
 * signer or add an issuer to the stored anchors: a row whose MAC does not match is not used (fail closed).
 *
 * <p>Without a key there is no MAC: only the {@code dev} profile allows that (the service refuses to save a source
 * otherwise), and rows are then not checked. Changing {@code DB_ENCRYPTION} invalidates every MAC: re-save each
 * source and refresh it.
 */
public final class TrustedListIntegrity {

    private static final String LABEL = "helix-trusted-lists-integrity-v1";

    private final byte[] key;

    private TrustedListIntegrity(final byte[] key) {
        this.key = key;
    }

    /** MACs keyed from {@code secret} (the DB_ENCRYPTION value); none when it is null or blank. */
    public static TrustedListIntegrity fromSecret(final String secret) {
        if (secret == null || secret.isBlank()) {
            return new TrustedListIntegrity(null);
        }
        return new TrustedListIntegrity(hmac(secret.getBytes(StandardCharsets.UTF_8),
                LABEL.getBytes(StandardCharsets.UTF_8)));
    }

    public static TrustedListIntegrity none() {
        return new TrustedListIntegrity(null);
    }

    public boolean enabled() {
        return key != null;
    }

    /** The MAC of the parts (each length-prefixed, so parts cannot be shifted into each other); null without a key. */
    public String mac(final Object... parts) {
        if (key == null) {
            return null;
        }
        final StringBuilder sb = new StringBuilder();
        for (final Object part : parts) {
            final String v = part == null ? "\u0000" : part.toString();
            sb.append(v.length()).append(':').append(v).append('|');
        }
        return Base64.getUrlEncoder().withoutPadding().encodeToString(
                hmac(key, sb.toString().getBytes(StandardCharsets.UTF_8)));
    }

    /** Whether {@code stored} is the MAC of the parts; always true without a key (dev only). */
    public boolean verify(final String stored, final Object... parts) {
        if (key == null) {
            return true;
        }
        return stored != null && MessageDigest.isEqual(stored.getBytes(StandardCharsets.US_ASCII),
                mac(parts).getBytes(StandardCharsets.US_ASCII));
    }

    private static byte[] hmac(final byte[] k, final byte[] data) {
        try {
            final Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(k, "HmacSHA256"));
            return mac.doFinal(data);
        } catch (final GeneralSecurityException e) {
            throw new IllegalStateException("HmacSHA256 is not available", e);
        }
    }
}
