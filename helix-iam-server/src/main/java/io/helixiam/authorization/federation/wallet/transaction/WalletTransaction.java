/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.wallet.transaction;

import io.helixiam.authorization.federation.wallet.WalletErrorCode;

import java.time.Instant;

/**
 * One verifier-side wallet login attempt (spec §6). It moves {@code CREATED → REQUEST_FETCHED → RESPONSE_RECEIVED →
 * VERIFIED → REDEEMED}, or to {@code FAILED} from {@code REQUEST_FETCHED}/{@code RESPONSE_RECEIVED}. Every transition
 * is atomic and single use, enforced by the {@link WalletTransactionStore}.
 *
 * <p><b>Same-device vs cross-device (spec §6, the chosen mechanism):</b> each transaction has two request ids. The QR
 * code carries {@link #crossDeviceRequestId}, the same-device button carries {@link #sameDeviceRequestId}.
 * {@link WalletTransactionStore#claimRequest} sets {@link #flow} from whichever id the wallet fetched first; only that
 * one can be fetched (again, until the response arrives: conformance ruling D2). The {@code direct_post} handler returns a {@code redirect_uri} only for
 * {@link Flow#SAME_DEVICE}. {@link #flow} is {@code null} until the request is fetched.
 *
 * <p>The request ids, {@link #responseId} and {@link #responseCode} are bearer secrets. Stores index them by their
 * SHA-256 only, and keep {@link #responseCode} only as its hash: a transaction read back from a store always has
 * {@code responseCode == null}. The only holder of a code is whoever created it: the {@code direct_post} handler for
 * same-device (passed to {@link WalletTransactionStore#complete}), or the bound browser for cross-device (returned once
 * by {@link WalletTransactionStore#issueResponseCode}).
 * {@link #encryptionJwkJson} is the ephemeral private decryption key; stores drop it when the transaction ends
 * (VERIFIED or FAILED). {@link #verifiedIdentityJson} is the mapped identity plus an audit summary, never the
 * {@code vp_token}.
 *
 * <p><b>Purpose (Task 21b).</b> A {@link Purpose#LOGIN} transaction signs a browser in (the broker's
 * {@code /broker/<alias>/callback}). A {@link Purpose#LINK} transaction is started from the account console by a
 * signed-in user, recorded server side as {@link #initiatingUserId}; it only ever links the verified wallet to that user
 * ({@code /account/wallet/<alias>/callback}) and never signs anyone in. A LINK transaction must carry its initiating
 * user, a LOGIN transaction must not carry one. Both survive every transition.
 */
public record WalletTransaction(String transactionId, String sameDeviceRequestId, String crossDeviceRequestId,
                                String responseId, String realmId, String providerAlias, String helixState,
                                String browserBindingHash, String nonce, String encryptionJwkJson, String dcqlQueryJson,
                                Flow flow, Status status, String responseCode, String verifiedIdentityJson,
                                WalletErrorCode failureCode, Instant createdAt, Instant expiresAt, Purpose purpose,
                                String initiatingUserId) {

    /** A {@link Purpose#LOGIN} transaction (no initiating user): the shape before Task 21b. */
    public WalletTransaction(final String transactionId, final String sameDeviceRequestId,
                             final String crossDeviceRequestId, final String responseId, final String realmId,
                             final String providerAlias, final String helixState, final String browserBindingHash,
                             final String nonce, final String encryptionJwkJson, final String dcqlQueryJson,
                             final Flow flow, final Status status, final String responseCode,
                             final String verifiedIdentityJson, final WalletErrorCode failureCode,
                             final Instant createdAt, final Instant expiresAt) {
        this(transactionId, sameDeviceRequestId, crossDeviceRequestId, responseId, realmId, providerAlias, helixState,
                browserBindingHash, nonce, encryptionJwkJson, dcqlQueryJson, flow, status, responseCode,
                verifiedIdentityJson, failureCode, createdAt, expiresAt, Purpose.LOGIN, null);
    }

    /** What a transaction is for (Task 21b): signing in, or linking the wallet to a signed-in user. */
    public enum Purpose { LOGIN, LINK }

    /** Which invocation path the wallet used; decided by which request id it fetched. */
    public enum Flow { SAME_DEVICE, CROSS_DEVICE }

    /** The transaction states (spec §6). {@code EXPIRED} is never stored: an expired transaction reads as absent. */
    public enum Status { CREATED, REQUEST_FETCHED, RESPONSE_RECEIVED, VERIFIED, FAILED, EXPIRED, REDEEMED }

    /** Whether this transaction has expired at {@code now} (expiry is exclusive: at {@code expiresAt} it is gone). */
    public boolean isExpiredAt(final Instant now) {
        return !now.isBefore(expiresAt);
    }

    WalletTransaction claimed(final Flow usedFlow) {
        return new WalletTransaction(transactionId, sameDeviceRequestId, crossDeviceRequestId, responseId, realmId,
                providerAlias, helixState, browserBindingHash, nonce, encryptionJwkJson, dcqlQueryJson, usedFlow,
                Status.REQUEST_FETCHED, responseCode, verifiedIdentityJson, failureCode, createdAt, expiresAt, purpose, initiatingUserId);
    }

    WalletTransaction withStatus(final Status newStatus) {
        return new WalletTransaction(transactionId, sameDeviceRequestId, crossDeviceRequestId, responseId, realmId,
                providerAlias, helixState, browserBindingHash, nonce, encryptionJwkJson, dcqlQueryJson, flow,
                newStatus, responseCode, verifiedIdentityJson, failureCode, createdAt, expiresAt, purpose, initiatingUserId);
    }

    /** VERIFIED: the key is dropped, the code is never kept in the record (stores keep only its hash). */
    WalletTransaction verified(final String identityJson) {
        return new WalletTransaction(transactionId, sameDeviceRequestId, crossDeviceRequestId, responseId, realmId,
                providerAlias, helixState, browserBindingHash, nonce, null, dcqlQueryJson, flow, Status.VERIFIED, null,
                identityJson, failureCode, createdAt, expiresAt, purpose, initiatingUserId);
    }

    /** FAILED: the key is dropped. */
    WalletTransaction failed(final WalletErrorCode code) {
        return new WalletTransaction(transactionId, sameDeviceRequestId, crossDeviceRequestId, responseId, realmId,
                providerAlias, helixState, browserBindingHash, nonce, null, dcqlQueryJson, flow, Status.FAILED, null,
                verifiedIdentityJson, code, createdAt, expiresAt, purpose, initiatingUserId);
    }

    /** REDEEMED: the stored identity is dropped (the caller got it with this transition). */
    WalletTransaction redeemedWithoutIdentity() {
        return new WalletTransaction(transactionId, sameDeviceRequestId, crossDeviceRequestId, responseId, realmId,
                providerAlias, helixState, browserBindingHash, nonce, null, dcqlQueryJson, flow, Status.REDEEMED, null,
                null, failureCode, createdAt, expiresAt, purpose, initiatingUserId);
    }

    /** Never print secrets: the request ids, response id/code, nonce, key and identity are left out. */
    @Override
    public String toString() {
        return "WalletTransaction[transactionId=" + transactionId + ", realmId=" + realmId + ", providerAlias="
                + providerAlias + ", purpose=" + purpose + ", flow=" + flow + ", status=" + status + ", failureCode=" + failureCode
                + ", expiresAt=" + expiresAt + "]";
    }
}
