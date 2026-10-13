/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.wallet.transaction;

import io.helixiam.authorization.federation.wallet.WalletErrorCode;
import io.helixiam.authorization.federation.wallet.transaction.WalletTransaction.Flow;
import io.helixiam.authorization.federation.wallet.transaction.WalletTransaction.Status;
import io.helixiam.common.startup.DeploymentProfile;
import io.helixiam.persistence.security.AttributeEncryption;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.TransactionTemplate;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.function.Supplier;

/**
 * Production readiness item 3: the PostgreSQL {@link WalletTransactionStore}, shared by every replica through the
 * database. Selected whenever the HTTP session store is {@code queue} (PostgreSQL), and whenever no Redis is
 * configured; so a multi-replica deployment without Redis needs no sticky sessions. Same semantics as
 * {@link RedisWalletTransactionStore}, and the same contract suite runs against both.
 *
 * <p><b>Layout.</b> One {@code wallet_transaction} row per transaction (Flyway V79 and {@code schema.sql}). The two
 * request ids, the response id and the response code are looked up by their SHA-256 only ({@link SecretHash}, unique
 * columns); the response code is stored ONLY as its hash. The request ids, the response id, the ephemeral private JWK
 * and the verified identity are encrypted with {@link AttributeEncryption}, which fails closed: a value it cannot
 * decrypt fails the read, never comes back as-is.
 *
 * <p><b>Atomicity.</b> Every transition is ONE conditional statement, {@code UPDATE … WHERE <key> AND status = ? AND
 * expires_at > ? RETURNING …} (or {@code DELETE … WHERE …}), committed in its own transaction. PostgreSQL row locks
 * serialise concurrent writers of a row, and a writer that waited re-checks the {@code WHERE} against the row the
 * winner left, so exactly one of any number of racing claims, completions, code issues or redeems succeeds. Nothing
 * is read first and then written. The time is the caller's clock (passed in, as in Redis), so a transaction is refused
 * from its expiry on, before the sweep deletes it; replicas need synchronised clocks (NTP), as for token lifetimes.
 *
 * <p><b>Constant time.</b> As in Redis, the browser binding (code issue) and the state and binding (redeem) are compared
 * in constant time in Java on the row the hash lookup found, and the {@code UPDATE} re-checks the binding and code hash
 * itself. A failed redeem never burns the transaction (see {@link RedisWalletTransactionStore}).
 *
 * <p><b>Encryption.</b> Outside the {@code dev} profile, {@link #create} refuses to persist anything when
 * {@code DB_ENCRYPTION} is not set; every transaction carries a private key.
 *
 * <p><b>Expiry.</b> An expired row reads as absent at once; {@link #sweep()} deletes expired rows and runs every
 * {@code helix.wallet.transaction-sweep-seconds} (default 60) once {@link #start()}ed.
 */
public class JdbcWalletTransactionStore implements WalletTransactionStore, AutoCloseable {

    private static final Logger LOG = LogManager.getLogger(JdbcWalletTransactionStore.class);
    private static final String ENCRYPTION_PROBE = "helix-encryption-probe";
    private static final String COLUMNS = "transaction_id, same_device_request, cross_device_request, response, "
            + "realm_id, provider_alias, helix_state, browser_binding, nonce, encryption_jwk, dcql_query, flow, status, "
            + "verified_identity, failure_code, created_at, expires_at, purpose, initiating_user_id";
    private static final String UNFINISHED = "('CREATED', 'REQUEST_FETCHED', 'RESPONSE_RECEIVED')";

    private final JdbcTemplate jdbc;
    private final TransactionTemplate tx;
    private final AttributeEncryption encryption;
    private final DeploymentProfile profile;
    private final Clock clock;
    private final boolean encrypted;
    private final Duration sweepInterval;
    private final RowMapper<WalletTransaction> rows = this::toTransaction;
    private ScheduledExecutorService sweeper;

    public JdbcWalletTransactionStore(final JdbcTemplate jdbc, final PlatformTransactionManager transactions,
                                      final AttributeEncryption encryption, final DeploymentProfile profile,
                                      final Clock clock) {
        this(jdbc, transactions, encryption, profile, clock, Duration.ofSeconds(60));
    }

    public JdbcWalletTransactionStore(final JdbcTemplate jdbc, final PlatformTransactionManager transactions,
                                      final AttributeEncryption encryption, final DeploymentProfile profile,
                                      final Clock clock, final Duration sweepInterval) {
        this.jdbc = jdbc;
        // The pool has auto-commit off, and a caller's transaction must not hold a transition back: each statement
        // commits on its own, at once, so every replica sees it. Never read-only (that would route to a replica).
        this.tx = new TransactionTemplate(transactions);
        this.tx.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRES_NEW);
        this.encryption = encryption;
        this.profile = profile;
        this.clock = clock;
        this.sweepInterval = sweepInterval;
        // AttributeEncryption without a key passes values through unchanged.
        this.encrypted = !ENCRYPTION_PROBE.equals(encryption.convertToDatabaseColumn(ENCRYPTION_PROBE));
    }

    /** Starts the periodic sweep of expired rows (no-op for a zero or negative interval, or when started). */
    public synchronized void start() {
        if (sweeper != null || sweepInterval.isZero() || sweepInterval.isNegative()) {
            return;
        }
        sweeper = Executors.newSingleThreadScheduledExecutor(runnable -> {
            final Thread thread = new Thread(runnable, "helix-wallet-tx-sweep");
            thread.setDaemon(true);
            return thread;
        });
        final long millis = sweepInterval.toMillis();
        sweeper.scheduleWithFixedDelay(this::sweepQuietly, millis, millis, TimeUnit.MILLISECONDS);
    }

    @Override
    public synchronized void close() {
        if (sweeper != null) {
            sweeper.shutdownNow();
            sweeper = null;
        }
    }

    /** Deletes every expired row; returns how many. */
    public int sweep() {
        final Integer deleted = write(() -> jdbc.update("DELETE FROM wallet_transaction WHERE expires_at <= ?", now()));
        return deleted == null ? 0 : deleted;
    }

    private void sweepQuietly() {
        try {
            final int deleted = sweep();
            if (deleted > 0) {
                LOG.debug("Swept {} expired wallet transaction(s)", deleted);
            }
        } catch (final RuntimeException e) {
            LOG.warn("Sweeping expired wallet transactions failed (retrying): {}", e.getClass().getSimpleName());
        }
    }

    @Override
    public void create(final WalletTransaction transaction) {
        WalletTransactionValidation.requireNew(transaction, clock.instant());
        if (!encrypted) {
            if (!profile.isDev()) {
                throw new IllegalStateException("Database encryption is not configured: set DB_ENCRYPTION before "
                        + "using the PostgreSQL wallet transaction store (it holds private decryption keys)");
            }
            LOG.warn("DB_ENCRYPTION is not set: wallet transaction {} keeps its private key in the database in "
                    + "plaintext (allowed only in the dev profile)", transaction.transactionId());
        }
        final Integer inserted = write(() -> jdbc.update("INSERT INTO wallet_transaction (transaction_id, "
                        + "same_device_request_hash, cross_device_request_hash, response_hash, same_device_request, "
                        + "cross_device_request, response, realm_id, provider_alias, helix_state, browser_binding, "
                        + "nonce, encryption_jwk, dcql_query, status, purpose, initiating_user_id, created_at, "
                        + "expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'CREATED', ?, ?, ?, ?) "
                        + "ON CONFLICT DO NOTHING",
                transaction.transactionId(), SecretHash.of(transaction.sameDeviceRequestId()),
                SecretHash.of(transaction.crossDeviceRequestId()), SecretHash.of(transaction.responseId()),
                encrypt(transaction.sameDeviceRequestId()), encrypt(transaction.crossDeviceRequestId()),
                encrypt(transaction.responseId()), transaction.realmId(), transaction.providerAlias(),
                transaction.helixState(), transaction.browserBindingHash(), transaction.nonce(),
                encrypt(transaction.encryptionJwkJson()), transaction.dcqlQueryJson(), transaction.purpose().name(),
                transaction.initiatingUserId(),
                transaction.createdAt() == null ? null : transaction.createdAt().toEpochMilli(),
                transaction.expiresAt().toEpochMilli()));
        if (inserted == null || inserted != 1) {
            throw new IllegalArgumentException("A wallet transaction with this id already exists");
        }
    }

    @Override
    public Optional<WalletTransaction> byTransactionId(final String id) {
        if (id == null) {
            return Optional.empty();
        }
        return one(() -> jdbc.query("SELECT " + COLUMNS + " FROM wallet_transaction WHERE transaction_id = ? "
                + "AND expires_at > ?", rows, id, now()));
    }

    @Override
    public Optional<WalletTransaction> claimRequest(final String requestId) {
        if (requestId == null) {
            return Optional.empty();
        }
        final String hash = SecretHash.of(requestId);
        // Whichever request id was fetched decides the flow; only one of the two can ever be (status = CREATED).
        return one(() -> jdbc.query("UPDATE wallet_transaction SET status = 'REQUEST_FETCHED', flow = CASE WHEN "
                + "same_device_request_hash = ? THEN 'SAME_DEVICE' ELSE 'CROSS_DEVICE' END "
                + "WHERE (same_device_request_hash = ? OR cross_device_request_hash = ?) AND status = 'CREATED' "
                + "AND expires_at > ? RETURNING " + COLUMNS, rows, hash, hash, hash, now()));
    }

    @Override
    public Optional<WalletTransaction> claimResponse(final String responseId) {
        if (responseId == null) {
            return Optional.empty();
        }
        return one(() -> jdbc.query("UPDATE wallet_transaction SET status = 'RESPONSE_RECEIVED' "
                + "WHERE response_hash = ? AND status = 'REQUEST_FETCHED' AND expires_at > ? RETURNING " + COLUMNS,
                rows, SecretHash.of(responseId), now()));
    }

    @Override
    public boolean discard(final String transactionId) {
        if (transactionId == null) {
            return false;
        }
        return Integer.valueOf(1).equals(write(() -> jdbc.update("DELETE FROM wallet_transaction "
                + "WHERE transaction_id = ? AND status IN " + UNFINISHED + " AND expires_at > ?", transactionId, now())));
    }

    @Override
    public boolean complete(final String transactionId, final String responseCode, final String verifiedIdentityJson) {
        if (transactionId == null) {
            return false;
        }
        // Same-device needs a code (the direct_post handler hands it to the wallet); cross-device takes none.
        final String flow = responseCode == null ? Flow.CROSS_DEVICE.name() : Flow.SAME_DEVICE.name();
        return Integer.valueOf(1).equals(write(() -> jdbc.update("UPDATE wallet_transaction SET status = 'VERIFIED', "
                        + "code_hash = ?, verified_identity = ?, encryption_jwk = NULL WHERE transaction_id = ? "
                        + "AND status = 'RESPONSE_RECEIVED' AND flow = ? AND expires_at > ?",
                responseCode == null ? null : SecretHash.of(responseCode), encrypt(verifiedIdentityJson),
                transactionId, flow, now())));
    }

    @Override
    public boolean fail(final String transactionId, final WalletErrorCode code) {
        if (transactionId == null || code == null) {
            return false;
        }
        return Integer.valueOf(1).equals(write(() -> jdbc.update("UPDATE wallet_transaction SET status = 'FAILED', "
                + "failure_code = ?, encryption_jwk = NULL WHERE transaction_id = ? AND status IN ('REQUEST_FETCHED', "
                + "'RESPONSE_RECEIVED') AND expires_at > ?", code.name(), transactionId, now())));
    }

    @Override
    public Optional<String> issueResponseCode(final String transactionId, final String browserBindingHash) {
        if (transactionId == null || browserBindingHash == null) {
            return Optional.empty();
        }
        final Optional<WalletTransaction> current = byTransactionId(transactionId);
        if (current.isEmpty() || !SecretHash.matches(browserBindingHash, current.get().browserBindingHash())) {
            return Optional.empty();
        }
        final String code = SecretHash.newSecret();
        final Integer issued = write(() -> jdbc.update("UPDATE wallet_transaction SET code_hash = ? "
                        + "WHERE transaction_id = ? AND status = 'VERIFIED' AND flow = 'CROSS_DEVICE' "
                        + "AND code_hash IS NULL AND browser_binding = ? AND expires_at > ?",
                SecretHash.of(code), transactionId, browserBindingHash, now()));
        return Integer.valueOf(1).equals(issued) ? Optional.of(code) : Optional.empty();
    }

    @Override
    public Optional<WalletTransaction> redeem(final String responseCode, final String helixState,
                                              final String browserBindingHash) {
        if (responseCode == null) {
            return Optional.empty();
        }
        final String codeHash = SecretHash.of(responseCode);
        final Optional<WalletTransaction> current = one(() -> jdbc.query("SELECT " + COLUMNS
                + " FROM wallet_transaction WHERE code_hash = ? AND expires_at > ?", rows, codeHash, now()));
        if (current.isEmpty()) {
            return Optional.empty();
        }
        // Constant-time, and both evaluated so the timing does not say which one was wrong (the code matched by hash).
        final boolean stateMatches = SecretHash.matches(helixState, current.get().helixState());
        final boolean bindingMatches = SecretHash.matches(browserBindingHash, current.get().browserBindingHash());
        if (current.get().status() != Status.VERIFIED || !(stateMatches & bindingMatches)) {
            return Optional.empty();
        }
        // One statement: the CTE locks the row and keeps its identity; the UPDATE moves VERIFIED -> REDEEMED and drops
        // it. A racing redeem waits on the lock, then finds REDEEMED and changes nothing.
        return one(() -> jdbc.query("WITH old AS (SELECT transaction_id, verified_identity FROM wallet_transaction "
                + "WHERE transaction_id = ? FOR UPDATE) UPDATE wallet_transaction t SET status = 'REDEEMED', "
                + "verified_identity = NULL FROM old WHERE t.transaction_id = old.transaction_id "
                + "AND t.status = 'VERIFIED' AND t.code_hash = ? AND t.expires_at > ? RETURNING "
                + prefixed("t.") + ", old.verified_identity AS redeemed_identity", this::toRedeemed,
                current.get().transactionId(), codeHash, now()));
    }

    // ------------------------------------------------------------------------------------------------ internals

    private <T> T write(final Supplier<T> statement) {
        return tx.execute(status -> statement.get());
    }

    private Optional<WalletTransaction> one(final Supplier<List<WalletTransaction>> query) {
        final List<WalletTransaction> found = tx.execute(status -> query.get());
        return found == null || found.isEmpty() ? Optional.empty() : Optional.of(found.get(0));
    }

    private long now() {
        return clock.instant().toEpochMilli();
    }

    private static String prefixed(final String prefix) {
        return prefix + COLUMNS.replace(", ", ", " + prefix);
    }

    private WalletTransaction toRedeemed(final ResultSet rs, final int row) throws SQLException {
        final WalletTransaction t = toTransaction(rs, row);
        return new WalletTransaction(t.transactionId(), t.sameDeviceRequestId(), t.crossDeviceRequestId(),
                t.responseId(), t.realmId(), t.providerAlias(), t.helixState(), t.browserBindingHash(), t.nonce(),
                t.encryptionJwkJson(), t.dcqlQueryJson(), t.flow(), t.status(), null,
                decrypt(rs.getString("redeemed_identity")), t.failureCode(), t.createdAt(), t.expiresAt(), t.purpose(),
                t.initiatingUserId());
    }

    private WalletTransaction toTransaction(final ResultSet rs, final int row) throws SQLException {
        final long createdAt = rs.getLong("created_at");
        final boolean noCreatedAt = rs.wasNull();
        final String flow = rs.getString("flow");
        final String failure = rs.getString("failure_code");
        return new WalletTransaction(rs.getString("transaction_id"), decrypt(rs.getString("same_device_request")),
                decrypt(rs.getString("cross_device_request")), decrypt(rs.getString("response")),
                rs.getString("realm_id"), rs.getString("provider_alias"), rs.getString("helix_state"),
                rs.getString("browser_binding"), rs.getString("nonce"), decrypt(rs.getString("encryption_jwk")),
                rs.getString("dcql_query"), flow == null ? null : Flow.valueOf(flow),
                Status.valueOf(rs.getString("status")), null, decrypt(rs.getString("verified_identity")),
                failure == null ? null : WalletErrorCode.valueOf(failure),
                noCreatedAt ? null : Instant.ofEpochMilli(createdAt), Instant.ofEpochMilli(rs.getLong("expires_at")),
                WalletTransaction.Purpose.valueOf(rs.getString("purpose")), rs.getString("initiating_user_id"));
    }

    private String encrypt(final String value) {
        return value == null ? null : encryption.convertToDatabaseColumn(value);
    }

    private String decrypt(final String value) {
        return value == null ? null : encryption.convertToEntityAttribute(value);
    }
}
