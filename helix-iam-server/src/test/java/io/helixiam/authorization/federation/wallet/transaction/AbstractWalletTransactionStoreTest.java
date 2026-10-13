/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.wallet.transaction;

import io.helixiam.authorization.federation.wallet.WalletErrorCode;
import io.helixiam.authorization.federation.wallet.transaction.WalletTransaction.Flow;
import io.helixiam.authorization.federation.wallet.transaction.WalletTransaction.Status;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * The contract every {@link WalletTransactionStore} must meet. {@link InMemoryWalletTransactionStoreTest} and
 * {@link RedisWalletTransactionStoreTest} run this same suite.
 */
abstract class AbstractWalletTransactionStoreTest {

    static final Duration TTL = Duration.ofSeconds(300);
    static final String JWK = "{\"kty\":\"EC\",\"crv\":\"P-256\",\"kid\":\"k1\",\"x\":\"WKn-ZIGevcwGIyyrzFoZNBdaq9_TsqzGl"
            + "96oc0CWuis\",\"y\":\"y77t-RvAHRKTsSGdIYUfweuOvwrvDD-Q3Hv5J0fSKbE\",\"d\":\"Hndv7ZZjs_ke8o9zXYo3iq-Yr8SewI5vrq"
            + "d0pAvEPqg\"}";
    static final String IDENTITY = "{\"subject\":\"NL-123\",\"attributes\":{\"given_name\":\"Erika\"},\"audit\":{}}";

    private static final SecureRandom RANDOM = new SecureRandom();

    final MutableClock clock = new MutableClock(Instant.parse("2026-10-12T10:00:00Z"));
    WalletTransactionStore store;

    /** A fresh, empty store reading time from {@code clock}. */
    abstract WalletTransactionStore newStore(Clock clock);

    @BeforeEach
    void setUpStore() {
        store = newStore(clock);
    }

    static String random() {
        final byte[] bytes = new byte[16];
        RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    WalletTransaction newTransaction() {
        final Instant now = clock.instant();
        return new WalletTransaction(random(), random(), random(), random(), "realm-a", "eudi", random(),
                random(), random(), JWK, "{\"credentials\":[]}", null, Status.CREATED, null, null, null, now,
                now.plus(TTL));
    }

    WalletTransaction created() {
        final WalletTransaction tx = newTransaction();
        store.create(tx);
        return tx;
    }

    WalletTransaction requestFetched() {
        return requestFetched(Flow.CROSS_DEVICE);
    }

    WalletTransaction requestFetched(final Flow flow) {
        final WalletTransaction tx = created();
        assertThat(store.claimRequest(flow == Flow.SAME_DEVICE ? tx.sameDeviceRequestId()
                : tx.crossDeviceRequestId())).isPresent();
        return tx;
    }

    /** Same-device: the {@code direct_post} handler supplies the response code to {@code complete}. */
    WalletTransaction responseReceived() {
        return responseReceived(Flow.SAME_DEVICE);
    }

    WalletTransaction responseReceived(final Flow flow) {
        final WalletTransaction tx = requestFetched(flow);
        assertThat(store.claimResponse(tx.responseId())).isPresent();
        return tx;
    }

    /** A same-device transaction completed with a response code (returned as {@link Verified#code()}). */
    Verified verified() {
        final WalletTransaction tx = responseReceived(Flow.SAME_DEVICE);
        final String code = random();
        assertThat(store.complete(tx.transactionId(), code, IDENTITY)).isTrue();
        return new Verified(tx, code);
    }

    /** A cross-device transaction completed without a code; no code has been issued yet. */
    WalletTransaction verifiedCrossDevice() {
        final WalletTransaction tx = responseReceived(Flow.CROSS_DEVICE);
        assertThat(store.complete(tx.transactionId(), null, IDENTITY)).isTrue();
        return tx;
    }

    static WalletTransaction copy(final WalletTransaction tx, final String sameDeviceRequestId,
                                  final String crossDeviceRequestId, final String responseId, final Instant createdAt,
                                  final Instant expiresAt) {
        return new WalletTransaction(tx.transactionId(), sameDeviceRequestId, crossDeviceRequestId, responseId,
                tx.realmId(), tx.providerAlias(), tx.helixState(), tx.browserBindingHash(), tx.nonce(),
                tx.encryptionJwkJson(), tx.dcqlQueryJson(), null, Status.CREATED, null, null, null, createdAt,
                expiresAt);
    }

    record Verified(WalletTransaction tx, String code) {
    }

    Status statusOf(final WalletTransaction tx) {
        return store.byTransactionId(tx.transactionId()).map(WalletTransaction::status).orElse(null);
    }

    // ------------------------------------------------------------------------------------------------ discard

    /** Task 18 fix round 1: a browser has one live wallet login; starting another discards the previous one. */
    @Test
    void discard_removesALiveTransaction_andItsIdsStopWorking() {
        final WalletTransaction created = created();
        final WalletTransaction fetched = requestFetched();
        final WalletTransaction received = responseReceived(Flow.CROSS_DEVICE);

        assertThat(store.discard(created.transactionId())).isTrue();
        assertThat(store.discard(fetched.transactionId())).isTrue();
        assertThat(store.discard(received.transactionId())).isTrue();

        assertThat(store.byTransactionId(created.transactionId())).isEmpty();
        assertThat(store.claimRequest(created.crossDeviceRequestId())).isEmpty();
        assertThat(store.claimResponse(fetched.responseId())).isEmpty();
        assertThat(store.complete(received.transactionId(), null, IDENTITY)).isFalse();
        assertThat(store.discard(created.transactionId())).as("already gone").isFalse();
    }

    @Test
    void discard_leavesFinishedTransactionsAndUnknownIdsAlone() {
        final Verified verified = verified();
        final WalletTransaction failed = requestFetched();
        assertThat(store.fail(failed.transactionId(), WalletErrorCode.WALLET_ERROR)).isTrue();

        assertThat(store.discard(verified.tx().transactionId())).isFalse();
        assertThat(store.discard(failed.transactionId())).isFalse();
        assertThat(store.discard(random())).isFalse();
        assertThat(store.discard(null)).isFalse();
        assertThat(statusOf(verified.tx())).isEqualTo(Status.VERIFIED);
        assertThat(statusOf(failed)).isEqualTo(Status.FAILED);
    }

    // ------------------------------------------------------------------------------------------------ create/lookup

    @Test
    void create_thenLookupById_returnsTheTransaction() {
        final WalletTransaction tx = created();

        final WalletTransaction read = store.byTransactionId(tx.transactionId()).orElseThrow();

        assertThat(read).isEqualTo(tx);
        assertThat(read.encryptionJwkJson()).isEqualTo(JWK);
    }

    @Test
    void lookupOfUnknownIds_isEmpty() {
        created();

        assertThat(store.byTransactionId(random())).isEmpty();
        assertThat(store.claimRequest(random())).isEmpty();
        assertThat(store.claimResponse(random())).isEmpty();
        assertThat(store.complete(random(), random(), IDENTITY)).isFalse();
        assertThat(store.fail(random(), WalletErrorCode.WALLET_ERROR)).isFalse();
        assertThat(store.redeem(random(), random(), random())).isEmpty();
    }

    @Test
    void create_twiceWithTheSameId_isRefused() {
        final WalletTransaction tx = created();

        assertThatThrownBy(() -> store.create(tx)).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void create_alreadyExpiredOrNotCreated_isRefused() {
        final WalletTransaction tx = newTransaction();
        final WalletTransaction expired = new WalletTransaction(tx.transactionId(), tx.sameDeviceRequestId(),
                tx.crossDeviceRequestId(), tx.responseId(), tx.realmId(), tx.providerAlias(), tx.helixState(),
                tx.browserBindingHash(), tx.nonce(), JWK, tx.dcqlQueryJson(), null, Status.CREATED, null, null, null,
                tx.createdAt(), clock.instant());

        assertThatThrownBy(() -> store.create(expired)).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> store.create(tx.withStatus(Status.VERIFIED)))
                .isInstanceOf(IllegalArgumentException.class);
        assertThat(store.byTransactionId(tx.transactionId())).isEmpty();
    }

    @Test
    void create_withALifetimeOutside60To900Seconds_isRefused() {
        final WalletTransaction tx = newTransaction();
        final Instant now = clock.instant();

        assertThatThrownBy(() -> store.create(copy(tx, tx.sameDeviceRequestId(), tx.crossDeviceRequestId(),
                tx.responseId(), now, now.plusSeconds(901)))).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> store.create(copy(tx, tx.sameDeviceRequestId(), tx.crossDeviceRequestId(),
                tx.responseId(), now, now.plusSeconds(59)))).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> store.create(copy(tx, tx.sameDeviceRequestId(), tx.crossDeviceRequestId(),
                tx.responseId(), null, now.plus(TTL)))).isInstanceOf(IllegalArgumentException.class);
        assertThat(store.byTransactionId(tx.transactionId())).isEmpty();

        store.create(copy(tx, tx.sameDeviceRequestId(), tx.crossDeviceRequestId(), tx.responseId(), now,
                now.plusSeconds(900)));
        assertThat(store.byTransactionId(tx.transactionId())).isPresent();
        final WalletTransaction other = newTransaction();
        store.create(copy(other, other.sameDeviceRequestId(), other.crossDeviceRequestId(), other.responseId(), now,
                now.plusSeconds(60)));
        assertThat(store.byTransactionId(other.transactionId())).isPresent();
    }

    @Test
    void create_withRepeatedBearerIds_isRefused() {
        final WalletTransaction tx = newTransaction();
        final String a = tx.sameDeviceRequestId();
        final String b = tx.crossDeviceRequestId();
        final Instant created = tx.createdAt();
        final Instant expires = tx.expiresAt();

        assertThatThrownBy(() -> store.create(copy(tx, a, a, tx.responseId(), created, expires)))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> store.create(copy(tx, a, b, a, created, expires)))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> store.create(copy(tx, a, b, b, created, expires)))
                .isInstanceOf(IllegalArgumentException.class);
        assertThat(store.byTransactionId(tx.transactionId())).isEmpty();
    }

    // ------------------------------------------------------------------------------------------------ claimRequest

    @Test
    void claimRequest_withTheCrossDeviceId_setsCrossDeviceFlow() {
        final WalletTransaction tx = created();

        final WalletTransaction claimed = store.claimRequest(tx.crossDeviceRequestId()).orElseThrow();

        assertThat(claimed.status()).isEqualTo(Status.REQUEST_FETCHED);
        assertThat(claimed.flow()).isEqualTo(Flow.CROSS_DEVICE);
        assertThat(claimed.encryptionJwkJson()).isEqualTo(JWK);
        assertThat(store.byTransactionId(tx.transactionId()).orElseThrow().flow()).isEqualTo(Flow.CROSS_DEVICE);
    }

    @Test
    void claimRequest_withTheSameDeviceId_setsSameDeviceFlow() {
        final WalletTransaction tx = created();

        assertThat(store.claimRequest(tx.sameDeviceRequestId()).orElseThrow().flow()).isEqualTo(Flow.SAME_DEVICE);
    }

    @Test
    void claimRequest_second_isEmpty_evenWithTheOtherRequestId() {
        final WalletTransaction tx = created();
        assertThat(store.claimRequest(tx.sameDeviceRequestId())).isPresent();

        assertThat(store.claimRequest(tx.sameDeviceRequestId())).isEmpty();
        assertThat(store.claimRequest(tx.crossDeviceRequestId())).isEmpty();
        assertThat(store.byTransactionId(tx.transactionId()).orElseThrow().flow()).isEqualTo(Flow.SAME_DEVICE);
    }

    @Test
    void claimRequest_withTheResponseIdOrTransactionId_isEmpty() {
        final WalletTransaction tx = created();

        assertThat(store.claimRequest(tx.responseId())).isEmpty();
        assertThat(store.claimRequest(tx.transactionId())).isEmpty();
        assertThat(statusOf(tx)).isEqualTo(Status.CREATED);
    }

    /** Same-device and cross-device fetches racing: exactly one wins, and the stored flow is the winner's. */
    @Test
    void claimRequest_sameAndCrossDeviceRacing_exactlyOneWins_andFlowMatchesTheWinner() throws Exception {
        final WalletTransaction tx = created();
        final List<Optional<WalletTransaction>> results = race(20, i -> store.claimRequest(
                i % 2 == 0 ? tx.sameDeviceRequestId() : tx.crossDeviceRequestId()));

        final List<WalletTransaction> winners = results.stream().flatMap(Optional::stream).toList();
        assertThat(winners).hasSize(1);
        final WalletTransaction stored = store.byTransactionId(tx.transactionId()).orElseThrow();
        assertThat(stored.status()).isEqualTo(Status.REQUEST_FETCHED);
        assertThat(stored.flow()).isEqualTo(winners.get(0).flow()).isNotNull();
    }

    // ------------------------------------------------------------------------------------------------ claimResponse

    @Test
    void claimResponse_beforeTheRequestWasFetched_isEmpty() {
        final WalletTransaction tx = created();

        assertThat(store.claimResponse(tx.responseId())).isEmpty();
        assertThat(statusOf(tx)).isEqualTo(Status.CREATED);
    }

    @Test
    void claimResponse_movesToResponseReceived_andTheSecondIsEmpty() {
        final WalletTransaction tx = requestFetched();

        final WalletTransaction claimed = store.claimResponse(tx.responseId()).orElseThrow();

        assertThat(claimed.status()).isEqualTo(Status.RESPONSE_RECEIVED);
        assertThat(claimed.encryptionJwkJson()).isEqualTo(JWK);
        assertThat(claimed.nonce()).isEqualTo(tx.nonce());
        assertThat(store.claimResponse(tx.responseId())).isEmpty();
    }

    @Test
    void claimResponse_withARequestId_isEmpty() {
        final WalletTransaction tx = requestFetched();

        assertThat(store.claimResponse(tx.crossDeviceRequestId())).isEmpty();
        assertThat(statusOf(tx)).isEqualTo(Status.REQUEST_FETCHED);
    }

    /** Review Focus 2: concurrent duplicate {@code direct_post} submissions give exactly one success. */
    @Test
    void claimResponse_from20ThreadsAtOnce_exactlyOneWins() throws Exception {
        final WalletTransaction tx = requestFetched();

        final List<Optional<WalletTransaction>> results = race(20, i -> store.claimResponse(tx.responseId()));

        assertThat(results.stream().filter(Optional::isPresent).count()).isEqualTo(1);
        assertThat(statusOf(tx)).isEqualTo(Status.RESPONSE_RECEIVED);
    }

    /** Runs {@code action} on {@code threads} threads released together by one latch; returns every result. */
    static <T> List<T> race(final int threads, final java.util.function.IntFunction<T> action) throws Exception {
        final CountDownLatch ready = new CountDownLatch(threads);
        final CountDownLatch go = new CountDownLatch(1);
        final ExecutorService pool = Executors.newFixedThreadPool(threads);
        try {
            final List<Future<T>> futures = new ArrayList<>();
            for (int i = 0; i < threads; i++) {
                final int index = i;
                futures.add(pool.submit(() -> {
                    ready.countDown();
                    go.await();
                    return action.apply(index);
                }));
            }
            assertThat(ready.await(10, TimeUnit.SECONDS)).isTrue();
            go.countDown();
            final List<T> results = new ArrayList<>();
            for (final Future<T> future : futures) {
                results.add(future.get(30, TimeUnit.SECONDS));
            }
            return results;
        } finally {
            pool.shutdownNow();
        }
    }

    // ------------------------------------------------------------------------------------------------ complete/fail

    @Test
    void complete_fromResponseReceived_verifies_dropsTheKey_andNeverReturnsTheCode() {
        final WalletTransaction tx = responseReceived();

        assertThat(store.complete(tx.transactionId(), random(), IDENTITY)).isTrue();

        final WalletTransaction read = store.byTransactionId(tx.transactionId()).orElseThrow();
        assertThat(read.status()).isEqualTo(Status.VERIFIED);
        assertThat(read.verifiedIdentityJson()).isEqualTo(IDENTITY);
        assertThat(read.encryptionJwkJson()).isNull();
        assertThat(read.responseCode()).isNull();
    }

    @Test
    void complete_fromAnyOtherState_isANoOp() {
        final WalletTransaction created = created();
        assertThat(store.complete(created.transactionId(), random(), IDENTITY)).isFalse();
        assertThat(statusOf(created)).isEqualTo(Status.CREATED);

        final WalletTransaction fetched = requestFetched();
        assertThat(store.complete(fetched.transactionId(), random(), IDENTITY)).isFalse();
        assertThat(statusOf(fetched)).isEqualTo(Status.REQUEST_FETCHED);

        final Verified verified = verified();
        assertThat(store.complete(verified.tx().transactionId(), random(), "{}")).isFalse();
        assertThat(store.byTransactionId(verified.tx().transactionId()).orElseThrow().verifiedIdentityJson())
                .isEqualTo(IDENTITY);
        assertThat(store.redeem(verified.code(), verified.tx().helixState(), verified.tx().browserBindingHash()))
                .isPresent();
    }

    @Test
    void fail_fromRequestFetchedOrResponseReceived_marksFailed_andDropsTheKey() {
        final WalletTransaction fetched = requestFetched();
        assertThat(store.fail(fetched.transactionId(), WalletErrorCode.WALLET_ACCESS_DENIED)).isTrue();
        final WalletTransaction read = store.byTransactionId(fetched.transactionId()).orElseThrow();
        assertThat(read.status()).isEqualTo(Status.FAILED);
        assertThat(read.failureCode()).isEqualTo(WalletErrorCode.WALLET_ACCESS_DENIED);
        assertThat(read.encryptionJwkJson()).isNull();

        final WalletTransaction received = responseReceived();
        assertThat(store.fail(received.transactionId(), WalletErrorCode.NONCE_MISMATCH)).isTrue();
        assertThat(store.byTransactionId(received.transactionId()).orElseThrow().failureCode())
                .isEqualTo(WalletErrorCode.NONCE_MISMATCH);
        assertThat(store.complete(received.transactionId(), random(), IDENTITY)).isFalse();
    }

    @Test
    void fail_fromCreatedVerifiedOrFailed_isANoOp() {
        final WalletTransaction created = created();
        assertThat(store.fail(created.transactionId(), WalletErrorCode.WALLET_ERROR)).isFalse();
        assertThat(statusOf(created)).isEqualTo(Status.CREATED);

        final Verified verified = verified();
        assertThat(store.fail(verified.tx().transactionId(), WalletErrorCode.WALLET_ERROR)).isFalse();
        assertThat(statusOf(verified.tx())).isEqualTo(Status.VERIFIED);

        final WalletTransaction failed = requestFetched();
        assertThat(store.fail(failed.transactionId(), WalletErrorCode.WALLET_ACCESS_DENIED)).isTrue();
        assertThat(store.fail(failed.transactionId(), WalletErrorCode.REPLAY)).isFalse();
        assertThat(store.byTransactionId(failed.transactionId()).orElseThrow().failureCode())
                .isEqualTo(WalletErrorCode.WALLET_ACCESS_DENIED);
    }

    @Test
    void complete_sameDevice_requiresAResponseCode() {
        final WalletTransaction tx = responseReceived(Flow.SAME_DEVICE);

        assertThat(store.complete(tx.transactionId(), null, IDENTITY)).isFalse();
        assertThat(statusOf(tx)).isEqualTo(Status.RESPONSE_RECEIVED);
        assertThat(store.issueResponseCode(tx.transactionId(), tx.browserBindingHash())).isEmpty();
    }

    @Test
    void complete_crossDevice_takesNoResponseCode() {
        final WalletTransaction tx = responseReceived(Flow.CROSS_DEVICE);
        final String walletSideCode = random();

        assertThat(store.complete(tx.transactionId(), walletSideCode, IDENTITY)).isFalse();
        assertThat(statusOf(tx)).isEqualTo(Status.RESPONSE_RECEIVED);

        assertThat(store.complete(tx.transactionId(), null, IDENTITY)).isTrue();
        final WalletTransaction read = store.byTransactionId(tx.transactionId()).orElseThrow();
        assertThat(read.status()).isEqualTo(Status.VERIFIED);
        assertThat(read.encryptionJwkJson()).isNull();
        assertThat(store.redeem(walletSideCode, tx.helixState(), tx.browserBindingHash())).isEmpty();
    }

    // ------------------------------------------------------------------------------------------------ issueResponseCode

    @Test
    void issueResponseCode_crossDeviceVerified_returnsACodeOnce_thatRedeems() {
        final WalletTransaction tx = verifiedCrossDevice();

        final String code = store.issueResponseCode(tx.transactionId(), tx.browserBindingHash()).orElseThrow();

        assertThat(Base64.getUrlDecoder().decode(code)).hasSize(16);
        assertThat(store.issueResponseCode(tx.transactionId(), tx.browserBindingHash())).isEmpty();
        assertThat(store.byTransactionId(tx.transactionId()).orElseThrow().responseCode()).isNull();
        final WalletTransaction redeemed = store.redeem(code, tx.helixState(), tx.browserBindingHash()).orElseThrow();
        assertThat(redeemed.verifiedIdentityJson()).isEqualTo(IDENTITY);
        assertThat(store.redeem(code, tx.helixState(), tx.browserBindingHash())).isEmpty();
    }

    @Test
    void issueResponseCode_withAWrongBinding_isEmpty_andDoesNotUseUpTheIssue() {
        final WalletTransaction tx = verifiedCrossDevice();

        assertThat(store.issueResponseCode(tx.transactionId(), random())).isEmpty();
        assertThat(store.issueResponseCode(tx.transactionId(), null)).isEmpty();

        assertThat(store.issueResponseCode(tx.transactionId(), tx.browserBindingHash())).isPresent();
    }

    @Test
    void issueResponseCode_forASameDeviceTransaction_isEmpty() {
        final Verified v = verified();

        assertThat(store.issueResponseCode(v.tx().transactionId(), v.tx().browserBindingHash())).isEmpty();
        assertThat(store.redeem(v.code(), v.tx().helixState(), v.tx().browserBindingHash())).isPresent();
    }

    @Test
    void issueResponseCode_beforeVerifiedOrAfterFailure_isEmpty() {
        final WalletTransaction created = created();
        final WalletTransaction fetched = requestFetched(Flow.CROSS_DEVICE);
        final WalletTransaction received = responseReceived(Flow.CROSS_DEVICE);
        final WalletTransaction failed = requestFetched(Flow.CROSS_DEVICE);
        assertThat(store.fail(failed.transactionId(), WalletErrorCode.WALLET_ACCESS_DENIED)).isTrue();

        for (final WalletTransaction tx : List.of(created, fetched, received, failed)) {
            assertThat(store.issueResponseCode(tx.transactionId(), tx.browserBindingHash())).as(tx.toString())
                    .isEmpty();
        }
        assertThat(store.issueResponseCode(random(), random())).isEmpty();
        assertThat(store.issueResponseCode(null, null)).isEmpty();
    }

    @Test
    void issueResponseCode_expired_isEmpty() {
        final WalletTransaction tx = verifiedCrossDevice();

        clock.advance(TTL);

        assertThat(store.issueResponseCode(tx.transactionId(), tx.browserBindingHash())).isEmpty();
    }

    @Test
    void issueResponseCode_from20ThreadsAtOnce_exactlyOneCode() throws Exception {
        final WalletTransaction tx = verifiedCrossDevice();

        final List<Optional<String>> results = race(20,
                i -> store.issueResponseCode(tx.transactionId(), tx.browserBindingHash()));

        final List<String> codes = results.stream().flatMap(Optional::stream).toList();
        assertThat(codes).hasSize(1);
        assertThat(store.redeem(codes.get(0), tx.helixState(), tx.browserBindingHash())).isPresent();
    }

    // ------------------------------------------------------------------------------------------------ redeem

    @Test
    void redeem_withAllThreeMatching_returnsTheIdentity_andTheSecondIsEmpty() {
        final Verified v = verified();

        final WalletTransaction redeemed = store.redeem(v.code(), v.tx().helixState(), v.tx().browserBindingHash())
                .orElseThrow();

        assertThat(redeemed.status()).isEqualTo(Status.REDEEMED);
        assertThat(redeemed.verifiedIdentityJson()).isEqualTo(IDENTITY);
        assertThat(redeemed.realmId()).isEqualTo("realm-a");
        assertThat(redeemed.responseCode()).isNull();
        assertThat(store.redeem(v.code(), v.tx().helixState(), v.tx().browserBindingHash())).isEmpty();
        final WalletTransaction after = store.byTransactionId(v.tx().transactionId()).orElseThrow();
        assertThat(after.status()).isEqualTo(Status.REDEEMED);
        assertThat(after.verifiedIdentityJson()).isNull();
    }

    @Test
    void redeem_withWrongStateBindingOrCode_isEmpty_andStaysVerified() {
        final Verified v = verified();

        assertThat(store.redeem(v.code(), random(), v.tx().browserBindingHash())).isEmpty();
        assertThat(store.redeem(v.code(), v.tx().helixState(), random())).isEmpty();
        assertThat(store.redeem(random(), v.tx().helixState(), v.tx().browserBindingHash())).isEmpty();
        assertThat(store.redeem(v.code(), null, null)).isEmpty();
        assertThat(statusOf(v.tx())).isEqualTo(Status.VERIFIED);
    }

    /**
     * Decision: failed redeems do not burn the transaction. A wrong code never reaches a transaction (codes are
     * 128-bit random and looked up by hash); a right code with a wrong state or binding means the code leaked, and
     * burning would let whoever holds it cancel the victim's login. State and binding are themselves unguessable.
     */
    @Test
    void redeem_repeatedFailures_doNotBurnTheTransaction() {
        final Verified v = verified();
        for (int i = 0; i < 25; i++) {
            assertThat(store.redeem(v.code(), random(), random())).isEmpty();
        }

        assertThat(statusOf(v.tx())).isEqualTo(Status.VERIFIED);
        assertThat(store.redeem(v.code(), v.tx().helixState(), v.tx().browserBindingHash())).isPresent();
    }

    @Test
    void redeem_beforeVerified_isEmpty() {
        final WalletTransaction tx = responseReceived();

        assertThat(store.redeem(random(), tx.helixState(), tx.browserBindingHash())).isEmpty();
        assertThat(statusOf(tx)).isEqualTo(Status.RESPONSE_RECEIVED);
    }

    // ------------------------------------------------------------------------------------------------ expiry

    @Test
    void expired_everyOperationIsEmpty_inEveryState() {
        final WalletTransaction created = created();
        final WalletTransaction fetched = requestFetched();
        final WalletTransaction received = responseReceived();
        final Verified verified = verified();

        clock.advance(TTL);

        for (final WalletTransaction tx : List.of(created, fetched, received, verified.tx())) {
            assertThat(store.byTransactionId(tx.transactionId())).isEmpty();
            assertThat(store.fail(tx.transactionId(), WalletErrorCode.TRANSACTION_EXPIRED)).isFalse();
        }
        assertThat(store.claimRequest(created.crossDeviceRequestId())).isEmpty();
        assertThat(store.claimRequest(created.sameDeviceRequestId())).isEmpty();
        assertThat(store.claimResponse(fetched.responseId())).isEmpty();
        assertThat(store.complete(received.transactionId(), random(), IDENTITY)).isFalse();
        assertThat(store.redeem(verified.code(), verified.tx().helixState(), verified.tx().browserBindingHash()))
                .isEmpty();
    }

    @Test
    void justBeforeExpiry_theTransactionStillWorks() {
        final WalletTransaction tx = created();

        clock.advance(TTL.minusMillis(1));

        assertThat(store.claimRequest(tx.crossDeviceRequestId())).isPresent();
    }

    // ------------------------------------------------------------------------------------------------ purpose

    /** Task 21b: a LINK transaction from the account console, started by {@code userId}. */
    WalletTransaction newLinkTransaction(final String userId) {
        final WalletTransaction tx = newTransaction();
        return new WalletTransaction(tx.transactionId(), tx.sameDeviceRequestId(), tx.crossDeviceRequestId(),
                tx.responseId(), tx.realmId(), tx.providerAlias(), tx.helixState(), tx.browserBindingHash(),
                tx.nonce(), tx.encryptionJwkJson(), tx.dcqlQueryJson(), null, Status.CREATED, null, null, null,
                tx.createdAt(), tx.expiresAt(), WalletTransaction.Purpose.LINK, userId);
    }

    @Test
    void aLoginTransaction_hasPurposeLogin_andNoInitiatingUser() {
        final WalletTransaction tx = created();

        final WalletTransaction read = store.byTransactionId(tx.transactionId()).orElseThrow();
        assertThat(read.purpose()).isEqualTo(WalletTransaction.Purpose.LOGIN);
        assertThat(read.initiatingUserId()).isNull();
    }

    @Test
    void aLinkTransaction_keepsItsPurposeAndInitiatingUser_throughEveryTransition() {
        final WalletTransaction tx = newLinkTransaction("user-42");
        store.create(tx);
        assertLink(store.byTransactionId(tx.transactionId()).orElseThrow());

        assertLink(store.claimRequest(tx.sameDeviceRequestId()).orElseThrow());
        assertLink(store.claimResponse(tx.responseId()).orElseThrow());
        final String code = random();
        assertThat(store.complete(tx.transactionId(), code, IDENTITY)).isTrue();
        assertLink(store.byTransactionId(tx.transactionId()).orElseThrow());
        assertLink(store.redeem(code, tx.helixState(), tx.browserBindingHash()).orElseThrow());
    }

    @Test
    void aFailedLinkTransaction_keepsItsPurpose() {
        final WalletTransaction tx = newLinkTransaction("user-42");
        store.create(tx);
        assertThat(store.claimRequest(tx.crossDeviceRequestId())).isPresent();

        assertThat(store.fail(tx.transactionId(), WalletErrorCode.WALLET_ERROR)).isTrue();

        assertLink(store.byTransactionId(tx.transactionId()).orElseThrow());
    }

    @Test
    void aLinkTransaction_needsItsInitiatingUser_andALogin_mustNotHaveOne() {
        assertThatThrownBy(() -> store.create(newLinkTransaction(null))).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> store.create(newLinkTransaction(" "))).isInstanceOf(IllegalArgumentException.class);
        final WalletTransaction login = newTransaction();
        final WalletTransaction loginWithUser = new WalletTransaction(login.transactionId(),
                login.sameDeviceRequestId(), login.crossDeviceRequestId(), login.responseId(), login.realmId(),
                login.providerAlias(), login.helixState(), login.browserBindingHash(), login.nonce(),
                login.encryptionJwkJson(), login.dcqlQueryJson(), null, Status.CREATED, null, null, null,
                login.createdAt(), login.expiresAt(), WalletTransaction.Purpose.LOGIN, "user-42");
        assertThatThrownBy(() -> store.create(loginWithUser)).isInstanceOf(IllegalArgumentException.class);
        final WalletTransaction noPurpose = new WalletTransaction(login.transactionId(),
                login.sameDeviceRequestId(), login.crossDeviceRequestId(), login.responseId(), login.realmId(),
                login.providerAlias(), login.helixState(), login.browserBindingHash(), login.nonce(),
                login.encryptionJwkJson(), login.dcqlQueryJson(), null, Status.CREATED, null, null, null,
                login.createdAt(), login.expiresAt(), null, null);
        assertThatThrownBy(() -> store.create(noPurpose)).isInstanceOf(IllegalArgumentException.class);
    }

    private static void assertLink(final WalletTransaction tx) {
        assertThat(tx.purpose()).isEqualTo(WalletTransaction.Purpose.LINK);
        assertThat(tx.initiatingUserId()).isEqualTo("user-42");
    }

    /** A clock tests can move. */
    static final class MutableClock extends Clock {
        private volatile Instant now;

        MutableClock(final Instant start) {
            this.now = start;
        }

        void advance(final Duration duration) {
            now = now.plus(duration);
        }

        @Override
        public ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(final ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return now;
        }
    }
}
