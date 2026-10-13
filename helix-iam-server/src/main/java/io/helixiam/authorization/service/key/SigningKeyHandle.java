/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.service.key;

/**
 * A resolved realm signing key (e.g. the OpenID4VP verifier access-certificate key). Callers get a {@link #signer()}
 * and the public certificate chain; the private key itself is never exposed, so a software store can later be swapped
 * for an HSM / KMS without changing callers.
 */
public interface SigningKeyHandle {
    String keyRef();                       // e.g. "software:acme/eudi-access-2026"
    com.nimbusds.jose.JWSAlgorithm algorithm();   // ES256 | ES384 | ES512
    java.util.List<java.security.cert.X509Certificate> certificateChain(); // leaf first, no root
    com.nimbusds.jose.JWSSigner signer();  // signs without exposing the private key to callers
}
