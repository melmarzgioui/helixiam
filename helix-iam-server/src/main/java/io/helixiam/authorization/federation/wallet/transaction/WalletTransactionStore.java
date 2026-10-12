/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.wallet.transaction;

import io.helixiam.authorization.federation.wallet.WalletErrorCode;

import java.util.Optional;

/**
 * Keeps the {@link WalletTransaction}s and makes every state transition atomic and single use.
 *
 * <p>Rules shared by every implementation:
 * <ul>
 *   <li>An expired transaction ({@code now >= expiresAt}) reads as absent: every method returns empty or
 *       {@code false} from that moment, even before the backing store has evicted it.</li>
 *   <li>Request ids, the response id and the response code are looked up by their SHA-256 only; the response code is
 *       stored only as its hash, so a transaction read back has {@code responseCode == null}.</li>
 *   <li>A transition from the wrong state changes nothing and returns empty / {@code false}.</li>
 * </ul>
 */
public interface WalletTransactionStore {

    /**
     * Stores a new transaction. It must be in {@link WalletTransaction.Status#CREATED}, carry both request ids and a
     * response id, and expire in the future.
     *
     * @throws IllegalArgumentException when the transaction is not a valid new transaction or its id already exists
     * @throws IllegalStateException when the store refuses to persist it (no at-rest encryption outside {@code dev},
     *                               or the in-memory store is full: then a
     *                               {@link WalletTransactionCapacityException}, which the wallet page shows as 503)
     */
    void create(WalletTransaction tx);

    Optional<WalletTransaction> byTransactionId(String id);

    /** Atomic CREATED→REQUEST_FETCHED, records which requestId (flow) was used. Empty if not CREATED / expired. */
    Optional<WalletTransaction> claimRequest(String requestId);

    /** Atomic REQUEST_FETCHED→RESPONSE_RECEIVED for responseId. Empty on second call. */
    Optional<WalletTransaction> claimResponse(String responseId);

    /**
     * Atomic RESPONSE_RECEIVED→VERIFIED. Keeps {@code verifiedIdentityJson} and drops the private decryption key.
     * <ul>
     *   <li>{@link WalletTransaction.Flow#SAME_DEVICE}: {@code responseCode} is required (the {@code direct_post}
     *       handler returns it to the wallet in the {@code redirect_uri}); it is stored as its hash only.</li>
     *   <li>{@link WalletTransaction.Flow#CROSS_DEVICE}: {@code responseCode} must be {@code null}; the browser that
     *       started the login gets a code from {@link #issueResponseCode}.</li>
     * </ul>
     *
     * @return {@code false} (and no change) when the transaction is absent, expired or not RESPONSE_RECEIVED, or the
     *         code does not fit the flow
     */
    boolean complete(String transactionId, String responseCode, String verifiedIdentityJson);

    /**
     * Atomic REQUEST_FETCHED or RESPONSE_RECEIVED → FAILED with {@code code}; drops the private decryption key.
     *
     * @return {@code false} (and no change) from any other state, or when absent or expired
     */
    boolean fail(String transactionId, WalletErrorCode code);

    /**
     * Cross-device only: atomically gives a VERIFIED transaction its response code, for the browser whose binding hash
     * matches (constant time). The code is 128-bit SecureRandom, base64url; only its hash is stored, and the raw code
     * is returned exactly once.
     *
     * @return empty when the transaction is absent, expired, not VERIFIED, same-device, already has a code, or the
     *         binding does not match (a wrong binding does not use up the issue)
     */
    Optional<String> issueResponseCode(String transactionId, String browserBindingHash);

    /**
     * Atomic VERIFIED→REDEEMED iff responseCode, helixState and browserBindingHash all match (compared in constant
     * time). Returns the transaction with its identity; the store then drops the identity. A mismatch returns empty
     * and leaves the transaction VERIFIED, however often it is tried (see the implementations for why it is not burnt).
     */
    Optional<WalletTransaction> redeem(String responseCode, String helixState, String browserBindingHash);
}
