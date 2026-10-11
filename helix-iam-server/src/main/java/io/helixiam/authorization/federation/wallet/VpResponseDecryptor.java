/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.wallet;

import com.fasterxml.jackson.databind.JsonNode;
import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.crypto.ECDHDecrypter;
import com.nimbusds.jose.jwk.ECKey;

import java.io.IOException;
import java.text.ParseException;
import java.util.Objects;
import java.util.Set;

/**
 * Decrypts an OpenID4VP {@code direct_post.jwt} Authorization Response (docs/eudi-wallet-spec-notes.md §1.3; HAIP
 * §2.1) and strictly validates the shape of the decrypted payload. The wallet encrypts to the Verifier's
 * per-transaction ephemeral EC key with {@code alg=ECDH-ES} (key agreement only, never a key-wrapping ECDH
 * variant) and one of the Verifier-advertised {@code enc} values; every header parameter that drives how the
 * ciphertext is processed is checked <em>before</em> any decryption is attempted, and the chosen algorithm is
 * never taken from the token itself beyond that check.
 *
 * <p>Every failure is a {@link WalletVerificationException}. A wrong {@code kid}, a response encrypted to a
 * different key, an authentication-tag failure and an {@code epk} on the wrong curve are all
 * {@code DECRYPTION_FAILED} with the same fixed, opaque message: the raw Nimbus failure reason is never exposed,
 * so none of these can be distinguished from one another to turn this endpoint into a decryption oracle.
 *
 * <p>The decrypted payload must be a strict JSON object (§8.1/§8.3: "top-level JSON members", no duplicate
 * members): either the wallet's error response (§8.5: {@code error}, optional {@code error_description}, optional
 * {@code state}) or the success response ({@code vp_token} as a JSON object, optional {@code state} as a string).
 * Anything else is {@code INVALID_RESPONSE}. A wallet error response is surfaced as {@code WALLET_ERROR}, distinct
 * from a malformed response; {@code error_description} is wallet-controlled free text and is never copied into the
 * exception detail.
 */
public final class VpResponseDecryptor {

    /** Checked on the raw compact string, before any parsing or base64 decoding. */
    public static final int MAX_COMPACT_JWE_BYTES = 256 * 1024;

    /** OpenID4VP 1.0 §8.3 / HAIP §2.1: key agreement only. Never a key-wrapping ECDH variant. */
    private static final JWEAlgorithm REQUIRED_ALG = JWEAlgorithm.ECDH_ES;

    /**
     * Decrypts and validates {@code compactJwe}.
     *
     * @param compactJwe     the {@code response} form parameter from a {@code direct_post.jwt} POST
     * @param transactionKey the Verifier's per-transaction EC key (with its private part); its {@code kid} is the
     *                       one advertised in {@code client_metadata.jwks} and must be present and so must be
     *                       exactly what the JWE {@code kid} header carries
     * @param allowedEnc     the Verifier's {@code encrypted_response_enc_values_supported}
     * @return the decoded success response
     * @throws WalletVerificationException on any failure; see the class javadoc for the codes used
     */
    public DecryptedResponse decrypt(final String compactJwe, final ECKey transactionKey,
            final Set<EncryptionMethod> allowedEnc) {
        Objects.requireNonNull(transactionKey, "transactionKey");
        Objects.requireNonNull(allowedEnc, "allowedEnc");

        if (compactJwe == null || compactJwe.length() > MAX_COMPACT_JWE_BYTES) {
            throw fail(WalletErrorCode.LIMIT_EXCEEDED,
                    "encrypted response exceeds " + MAX_COMPACT_JWE_BYTES + " bytes");
        }

        final JWEObject jwe;
        try {
            jwe = JWEObject.parse(compactJwe);
        } catch (final ParseException e) {
            throw fail(WalletErrorCode.INVALID_RESPONSE, "encrypted response is not a compact JWE");
        }

        checkHeader(jwe.getHeader(), transactionKey, allowedEnc);

        try {
            jwe.decrypt(new ECDHDecrypter(transactionKey));
        } catch (final JOSEException | RuntimeException e) {
            // Opaque on purpose (see class javadoc): a wrong key, a bad tag and a curve mismatch all land here and
            // must not be distinguishable from one another.
            throw fail(WalletErrorCode.DECRYPTION_FAILED, "encrypted response could not be decrypted");
        }

        return toDecryptedResponse(parsePayload(jwe.getPayload().toBytes()));
    }

    /** Every header check happens here, before {@link #decrypt} ever attempts to decrypt. */
    private static void checkHeader(final JWEHeader header, final ECKey transactionKey,
            final Set<EncryptionMethod> allowedEnc) {
        if (!REQUIRED_ALG.equals(header.getAlgorithm())) {
            throw fail(WalletErrorCode.ALGORITHM_NOT_ALLOWED, "JWE alg is not allowed");
        }
        if (transactionKey.getAlgorithm() != null && !transactionKey.getAlgorithm().equals(header.getAlgorithm())) {
            throw fail(WalletErrorCode.ALGORITHM_NOT_ALLOWED, "JWE alg does not match the transaction key");
        }
        if (header.getEncryptionMethod() == null || !allowedEnc.contains(header.getEncryptionMethod())) {
            throw fail(WalletErrorCode.ALGORITHM_NOT_ALLOWED, "JWE enc is not allowed");
        }
        if (header.getCompressionAlgorithm() != null) {
            // RFC 7516 §4.1.3 "zip". OpenID4VP never compresses the response (§8.3: "an unsigned, encrypted JWT"),
            // so a zip header is never a conforming wallet and only widens the attack surface to decompression
            // bombs. Treated the same as an alg/enc the Verifier does not allow (the allow-list of compression
            // algorithms is empty) rather than INVALID_RESPONSE, because like alg/enc it is a cryptographic
            // processing choice checked on the header, before any decoding of the body is attempted.
            throw fail(WalletErrorCode.ALGORITHM_NOT_ALLOWED, "JWE zip is not allowed");
        }
        final String kid = header.getKeyID();
        if (kid == null || !kid.equals(transactionKey.getKeyID())) {
            // Opaque on purpose: indistinguishable from any other decryption failure below.
            throw fail(WalletErrorCode.DECRYPTION_FAILED, "encrypted response could not be decrypted");
        }
    }

    private static JsonNode parsePayload(final byte[] plaintext) {
        final JsonNode root;
        try {
            root = StrictJson.MAPPER.readTree(plaintext);
        } catch (final IOException e) {
            throw fail(WalletErrorCode.INVALID_RESPONSE, "decrypted payload is not strict JSON");
        }
        if (root == null || !root.isObject()) {
            throw fail(WalletErrorCode.INVALID_RESPONSE, "decrypted payload is not a JSON object");
        }
        return root;
    }

    private static DecryptedResponse toDecryptedResponse(final JsonNode root) {
        final JsonNode error = root.get("error");
        if (error != null && !error.isNull()) {
            if (!error.isTextual()) {
                throw fail(WalletErrorCode.INVALID_RESPONSE, "wallet error response 'error' is not a string");
            }
            // OpenID4VP §8.5: the wallet's error response, surfaced distinctly from a malformed response.
            // error_description is wallet-controlled free text and is deliberately left out of the exception
            // detail.
            throw fail(WalletErrorCode.WALLET_ERROR, "wallet returned an error response");
        }

        final JsonNode vpToken = root.get("vp_token");
        if (vpToken == null || !vpToken.isObject()) {
            throw fail(WalletErrorCode.INVALID_RESPONSE, "vp_token is missing or not a JSON object");
        }

        final JsonNode stateNode = root.get("state");
        final String state;
        if (stateNode == null || stateNode.isNull()) {
            state = null;
        } else if (stateNode.isTextual()) {
            state = stateNode.asText();
        } else {
            throw fail(WalletErrorCode.INVALID_RESPONSE, "state is not a string");
        }

        return new DecryptedResponse(vpToken, state);
    }

    private static WalletVerificationException fail(final WalletErrorCode code, final String safeDetail) {
        return new WalletVerificationException(code, safeDetail);
    }
}
