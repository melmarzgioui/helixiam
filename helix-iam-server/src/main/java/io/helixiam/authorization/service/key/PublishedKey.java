/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.service.key;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.List;

/**
 * A realm signing key as the JWKS and the SAML IdP publish it (server-internal, never serialised).
 *
 * <p>The private key is carried for every key because the SAML fallback certificate of a key without a certificate is
 * self-signed by that key; only the ACTIVE key's private key is ever used to sign tokens or assertions
 * ({@code RealmJwkSource} attaches it to the ACTIVE JWK only).
 *
 * @param status    PENDING, ACTIVE or ROTATED
 * @param algorithm RS256 or ES256
 * @param chain     the certificate chain, leaf first; empty when the key has none
 */
public record PublishedKey(String keyId, String status, String algorithm, PublicKey publicKey, PrivateKey privateKey,
                           List<X509Certificate> chain) {

    public boolean active() {
        return "ACTIVE".equals(status);
    }

    public X509Certificate leaf() {
        return chain == null || chain.isEmpty() ? null : chain.get(0);
    }

    @Override
    public String toString() {
        return "PublishedKey[" + keyId + ", " + status + ", " + algorithm + "]"; // never key material
    }
}
