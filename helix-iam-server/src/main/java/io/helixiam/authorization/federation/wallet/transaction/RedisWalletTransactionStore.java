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
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.script.DefaultRedisScript;
import org.springframework.data.redis.core.script.RedisScript;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.TimeUnit;

/**
 * The multi-replica {@link WalletTransactionStore}: selected when {@code helix.iam.session-store=redis} or
 * {@code helix.iam.token-store=redis}, on the same {@link RedisConnectionFactory} as those stores.
 *
 * <p><b>Layout.</b> One hash per transaction, {@code helix:wallet:tx:{transactionId}}, plus string index keys
 * {@code helix:wallet:req:{sha256(requestId)}} (two per transaction), {@code helix:wallet:resp:{sha256(responseId)}}
 * and, once a code exists ({@code complete} for same-device, {@code issueResponseCode} for cross-device),
 * {@code helix:wallet:code:{sha256(responseCode)}}, each holding the transaction id. Every key
 * expires with the transaction. The index keys hold hashes so a key dump gives nobody a request id or a redeemable
 * code; inside the hash the request ids, the response id, the private JWK and the verified identity are encrypted with
 * {@link AttributeEncryption}, and the response code is stored only as its hash.
 *
 * <p><b>Atomicity.</b> Each transition is one Lua script on the transaction hash alone: it checks {@code expiresAt}
 * against the caller's clock (passed in, so an expired transaction is refused before Redis evicts it), then the
 * status and the presented secret's hash, then sets the new state. Index lookups are plain {@code GET}s before the
 * script; a stale index entry is harmless because the script re-checks the hash it points to. Keeping each script to
 * one key keeps the store usable on Redis Cluster.
 *
 * <p><b>Encryption.</b> Outside the {@code dev} profile, {@link #create} refuses to persist anything when
 * {@code DB_ENCRYPTION} is not set (the Task 5 rule for private keys); every transaction carries one.
 *
 * <p><b>Failed redeems</b> do not burn the transaction: a wrong code finds no transaction at all (codes are 128-bit
 * random), and a right code with a wrong state or binding means the code leaked, so burning it would only let the
 * holder cancel the victim's login.
 */
public class RedisWalletTransactionStore implements WalletTransactionStore {

    private static final Logger LOG = LogManager.getLogger(RedisWalletTransactionStore.class);

    static final String TX_PREFIX = "helix:wallet:tx:";
    static final String REQUEST_PREFIX = "helix:wallet:req:";
    static final String RESPONSE_PREFIX = "helix:wallet:resp:";
    static final String CODE_PREFIX = "helix:wallet:code:";

    private static final String ENCRYPTION_PROBE = "helix-encryption-probe";

    // Hash fields.
    private static final String ID = "id";
    private static final String SAME_DEVICE_REQUEST = "sdReq";
    private static final String CROSS_DEVICE_REQUEST = "cdReq";
    private static final String RESPONSE = "resp";
    private static final String SAME_DEVICE_REQUEST_HASH = "sdReqHash";
    private static final String CROSS_DEVICE_REQUEST_HASH = "cdReqHash";
    private static final String RESPONSE_HASH = "respHash";
    private static final String CODE_HASH = "codeHash";
    private static final String REALM = "realm";
    private static final String ALIAS = "alias";
    private static final String STATE = "state";
    private static final String BINDING = "binding";
    private static final String NONCE = "nonce";
    private static final String JWK = "jwk";
    private static final String DCQL = "dcql";
    private static final String FLOW = "flow";
    private static final String STATUS = "status";
    private static final String IDENTITY = "identity";
    private static final String FAILURE = "failure";
    private static final String CREATED_AT = "createdAt";
    private static final String EXPIRES_AT = "expiresAt";

    /** Shared prologue: KEYS[1] is the hash, ARGV[1] is now (epoch ms). Returns false when absent or expired. */
    private static final String LIVE = """
            local exp = redis.call('HGET', KEYS[1], 'expiresAt')
            if not exp or tonumber(ARGV[1]) >= tonumber(exp) then return false end
            local status = redis.call('HGET', KEYS[1], 'status')
            """;

    /** ARGV[1] = ttl ms; ARGV[2..] = field, value pairs. */
    private static final RedisScript<Long> CREATE = new DefaultRedisScript<>("""
            if redis.call('EXISTS', KEYS[1]) == 1 then return 0 end
            redis.call('HSET', KEYS[1], unpack(ARGV, 2))
            redis.call('PEXPIRE', KEYS[1], ARGV[1])
            return 1
            """, Long.class);

    /** ARGV[2] = sha256(requestId). */
    @SuppressWarnings("rawtypes")
    private static final RedisScript<List> CLAIM_REQUEST = new DefaultRedisScript<>(LIVE + """
            if status ~= 'CREATED' then return false end
            local flow
            if redis.call('HGET', KEYS[1], 'sdReqHash') == ARGV[2] then flow = 'SAME_DEVICE'
            elseif redis.call('HGET', KEYS[1], 'cdReqHash') == ARGV[2] then flow = 'CROSS_DEVICE'
            else return false end
            redis.call('HSET', KEYS[1], 'status', 'REQUEST_FETCHED', 'flow', flow)
            return redis.call('HGETALL', KEYS[1])
            """, List.class);

    /** ARGV[2] = sha256(responseId). */
    @SuppressWarnings("rawtypes")
    private static final RedisScript<List> CLAIM_RESPONSE = new DefaultRedisScript<>(LIVE + """
            if status ~= 'REQUEST_FETCHED' then return false end
            if redis.call('HGET', KEYS[1], 'respHash') ~= ARGV[2] then return false end
            redis.call('HSET', KEYS[1], 'status', 'RESPONSE_RECEIVED')
            return redis.call('HGETALL', KEYS[1])
            """, List.class);

    /**
     * ARGV[2] = sha256(responseCode) or '' for none, ARGV[3] = encrypted identity or '' for none. Same-device needs a
     * code (the direct_post handler hands it to the wallet); cross-device takes none (see ISSUE_CODE).
     */
    private static final RedisScript<Long> COMPLETE = new DefaultRedisScript<>(LIVE + """
            if status ~= 'RESPONSE_RECEIVED' then return 0 end
            local flow = redis.call('HGET', KEYS[1], 'flow')
            if flow == 'SAME_DEVICE' then
              if ARGV[2] == '' then return 0 end
            elseif flow ~= 'CROSS_DEVICE' or ARGV[2] ~= '' then return 0 end
            redis.call('HSET', KEYS[1], 'status', 'VERIFIED')
            if ARGV[2] ~= '' then redis.call('HSET', KEYS[1], 'codeHash', ARGV[2]) end
            if ARGV[3] ~= '' then redis.call('HSET', KEYS[1], 'identity', ARGV[3]) end
            redis.call('HDEL', KEYS[1], 'jwk')
            return 1
            """, Long.class);

    /**
     * ARGV[2] = sha256(new code), ARGV[3] = browser binding hash (already compared in constant time by the caller;
     * re-checked here). Only a VERIFIED cross-device transaction without a code yet gets one.
     */
    private static final RedisScript<Long> ISSUE_CODE = new DefaultRedisScript<>(LIVE + """
            if status ~= 'VERIFIED' then return 0 end
            if redis.call('HGET', KEYS[1], 'flow') ~= 'CROSS_DEVICE' then return 0 end
            if redis.call('HEXISTS', KEYS[1], 'codeHash') == 1 then return 0 end
            if redis.call('HGET', KEYS[1], 'binding') ~= ARGV[3] then return 0 end
            redis.call('HSET', KEYS[1], 'codeHash', ARGV[2])
            return 1
            """, Long.class);

    /** ARGV[2] = failure code. */
    private static final RedisScript<Long> FAIL = new DefaultRedisScript<>(LIVE + """
            if status ~= 'REQUEST_FETCHED' and status ~= 'RESPONSE_RECEIVED' then return 0 end
            redis.call('HSET', KEYS[1], 'status', 'FAILED', 'failure', ARGV[2])
            redis.call('HDEL', KEYS[1], 'jwk')
            return 1
            """, Long.class);

    /** ARGV[2] = sha256(responseCode), already compared in constant time by the caller; re-checked here. */
    @SuppressWarnings("rawtypes")
    private static final RedisScript<List> REDEEM = new DefaultRedisScript<>(LIVE + """
            if status ~= 'VERIFIED' then return false end
            if redis.call('HGET', KEYS[1], 'codeHash') ~= ARGV[2] then return false end
            redis.call('HSET', KEYS[1], 'status', 'REDEEMED')
            local snapshot = redis.call('HGETALL', KEYS[1])
            redis.call('HDEL', KEYS[1], 'identity')
            return snapshot
            """, List.class);

    private final StringRedisTemplate redis;
    private final AttributeEncryption encryption;
    private final DeploymentProfile profile;
    private final Clock clock;
    private final boolean encrypted;

    public RedisWalletTransactionStore(final RedisConnectionFactory connectionFactory,
                                       final AttributeEncryption encryption, final DeploymentProfile profile,
                                       final Clock clock) {
        this.redis = new StringRedisTemplate(connectionFactory);
        this.encryption = encryption;
        this.profile = profile;
        this.clock = clock;
        // AttributeEncryption without a key passes values through unchanged.
        this.encrypted = !ENCRYPTION_PROBE.equals(encryption.convertToDatabaseColumn(ENCRYPTION_PROBE));
    }

    @Override
    public void create(final WalletTransaction tx) {
        final Instant now = clock.instant();
        WalletTransactionValidation.requireNew(tx, now);
        if (!encrypted) {
            if (!profile.isDev()) {
                throw new IllegalStateException("Database encryption is not configured: set DB_ENCRYPTION before "
                        + "using the Redis wallet transaction store (it holds private decryption keys)");
            }
            LOG.warn("DB_ENCRYPTION is not set: wallet transaction {} keeps its private key in Redis in plaintext "
                    + "(allowed only in the dev profile)", tx.transactionId());
        }
        final long ttlMillis = Duration.between(now, tx.expiresAt()).toMillis();
        final String sameDeviceHash = SecretHash.of(tx.sameDeviceRequestId());
        final String crossDeviceHash = SecretHash.of(tx.crossDeviceRequestId());
        final String responseHash = SecretHash.of(tx.responseId());

        final List<String> args = new ArrayList<>();
        args.add(Long.toString(ttlMillis));
        put(args, ID, tx.transactionId());
        put(args, SAME_DEVICE_REQUEST, encrypt(tx.sameDeviceRequestId()));
        put(args, CROSS_DEVICE_REQUEST, encrypt(tx.crossDeviceRequestId()));
        put(args, RESPONSE, encrypt(tx.responseId()));
        put(args, SAME_DEVICE_REQUEST_HASH, sameDeviceHash);
        put(args, CROSS_DEVICE_REQUEST_HASH, crossDeviceHash);
        put(args, RESPONSE_HASH, responseHash);
        put(args, REALM, tx.realmId());
        put(args, ALIAS, tx.providerAlias());
        put(args, STATE, tx.helixState());
        put(args, BINDING, tx.browserBindingHash());
        put(args, NONCE, tx.nonce());
        put(args, JWK, encrypt(tx.encryptionJwkJson()));
        put(args, DCQL, tx.dcqlQueryJson());
        put(args, STATUS, Status.CREATED.name());
        put(args, CREATED_AT, tx.createdAt() == null ? null : Long.toString(tx.createdAt().toEpochMilli()));
        put(args, EXPIRES_AT, Long.toString(tx.expiresAt().toEpochMilli()));

        final Long created = redis.execute(CREATE, List.of(TX_PREFIX + tx.transactionId()), args.toArray());
        if (created == null || created != 1L) {
            throw new IllegalArgumentException("A wallet transaction with this id already exists");
        }
        final Duration ttl = Duration.ofMillis(ttlMillis);
        redis.opsForValue().set(REQUEST_PREFIX + sameDeviceHash, tx.transactionId(), ttl);
        redis.opsForValue().set(REQUEST_PREFIX + crossDeviceHash, tx.transactionId(), ttl);
        redis.opsForValue().set(RESPONSE_PREFIX + responseHash, tx.transactionId(), ttl);
    }

    @Override
    public Optional<WalletTransaction> byTransactionId(final String id) {
        if (id == null) {
            return Optional.empty();
        }
        return read(id).filter(fields -> live(fields, clock.instant())).map(this::toTransaction);
    }

    @Override
    public Optional<WalletTransaction> claimRequest(final String requestId) {
        if (requestId == null) {
            return Optional.empty();
        }
        final String hash = SecretHash.of(requestId);
        return transactionIdAt(REQUEST_PREFIX + hash).flatMap(id -> snapshot(CLAIM_REQUEST, id, hash));
    }

    @Override
    public Optional<WalletTransaction> claimResponse(final String responseId) {
        if (responseId == null) {
            return Optional.empty();
        }
        final String hash = SecretHash.of(responseId);
        return transactionIdAt(RESPONSE_PREFIX + hash).flatMap(id -> snapshot(CLAIM_RESPONSE, id, hash));
    }

    @Override
    public boolean complete(final String transactionId, final String responseCode, final String verifiedIdentityJson) {
        if (transactionId == null) {
            return false;
        }
        final String key = TX_PREFIX + transactionId;
        final String codeHash = responseCode == null ? "" : SecretHash.of(responseCode);
        if (responseCode != null) {
            final Long ttlMillis = redis.getExpire(key, TimeUnit.MILLISECONDS);
            if (ttlMillis == null || ttlMillis <= 0) {
                return false;
            }
            // Index first: the direct_post handler hands the wallet the code as soon as this returns, so the code
            // must already be redeemable. If the script then refuses, the entry points at a transaction whose
            // codeHash does not match, so it redeems nothing.
            redis.opsForValue().set(CODE_PREFIX + codeHash, transactionId, Duration.ofMillis(ttlMillis));
        }
        final String identity = verifiedIdentityJson == null ? "" : encrypt(verifiedIdentityJson);
        return Long.valueOf(1L).equals(redis.execute(COMPLETE, List.of(key), now(), codeHash, identity));
    }

    @Override
    public Optional<String> issueResponseCode(final String transactionId, final String browserBindingHash) {
        if (transactionId == null || browserBindingHash == null) {
            return Optional.empty();
        }
        final Optional<Map<String, String>> current = read(transactionId).filter(f -> live(f, clock.instant()));
        if (current.isEmpty() || !SecretHash.matches(browserBindingHash, current.get().get(BINDING))) {
            return Optional.empty();
        }
        final String key = TX_PREFIX + transactionId;
        final String code = SecretHash.newSecret();
        final String codeHash = SecretHash.of(code);
        if (!Long.valueOf(1L).equals(redis.execute(ISSUE_CODE, List.of(key), now(), codeHash, browserBindingHash))) {
            return Optional.empty();
        }
        // Index after the script: nobody but this caller holds the code yet, so nothing can try to redeem it before
        // the index exists. It expires with the transaction.
        final Long ttlMillis = redis.getExpire(key, TimeUnit.MILLISECONDS);
        if (ttlMillis == null || ttlMillis <= 0) {
            return Optional.empty();
        }
        redis.opsForValue().set(CODE_PREFIX + codeHash, transactionId, Duration.ofMillis(ttlMillis));
        return Optional.of(code);
    }

    @Override
    public boolean fail(final String transactionId, final WalletErrorCode code) {
        if (transactionId == null || code == null) {
            return false;
        }
        return Long.valueOf(1L).equals(redis.execute(FAIL, List.of(TX_PREFIX + transactionId), now(), code.name()));
    }

    @Override
    public Optional<WalletTransaction> redeem(final String responseCode, final String helixState,
                                              final String browserBindingHash) {
        if (responseCode == null) {
            return Optional.empty();
        }
        final String codeHash = SecretHash.of(responseCode);
        final Optional<String> id = transactionIdAt(CODE_PREFIX + codeHash);
        if (id.isEmpty()) {
            return Optional.empty();
        }
        final Optional<Map<String, String>> current = read(id.get()).filter(f -> live(f, clock.instant()));
        if (current.isEmpty()) {
            return Optional.empty();
        }
        final Map<String, String> fields = current.get();
        // Constant-time, and all three evaluated so the timing does not say which one was wrong.
        final boolean codeMatches = SecretHash.matches(codeHash, fields.get(CODE_HASH));
        final boolean stateMatches = SecretHash.matches(helixState, fields.get(STATE));
        final boolean bindingMatches = SecretHash.matches(browserBindingHash, fields.get(BINDING));
        if (!Status.VERIFIED.name().equals(fields.get(STATUS)) || !(codeMatches & stateMatches & bindingMatches)) {
            return Optional.empty();
        }
        return snapshot(REDEEM, id.get(), codeHash);
    }

    // ------------------------------------------------------------------------------------------------ internals

    private Optional<String> transactionIdAt(final String indexKey) {
        return Optional.ofNullable(redis.opsForValue().get(indexKey));
    }

    @SuppressWarnings("rawtypes")
    private Optional<WalletTransaction> snapshot(final RedisScript<List> script, final String transactionId,
                                                 final String secretHash) {
        final List<?> flat = redis.execute(script, List.of(TX_PREFIX + transactionId), now(), secretHash);
        // A refused transition returns a Lua false, which arrives as null or as a one-element [null] list.
        if (flat == null || flat.size() < 2) {
            return Optional.empty();
        }
        final Map<String, String> fields = new HashMap<>();
        for (int i = 0; i + 1 < flat.size(); i += 2) {
            fields.put(String.valueOf(flat.get(i)), String.valueOf(flat.get(i + 1)));
        }
        return Optional.of(toTransaction(fields));
    }

    private Optional<Map<String, String>> read(final String transactionId) {
        final Map<Object, Object> raw = redis.opsForHash().entries(TX_PREFIX + transactionId);
        if (raw.isEmpty()) {
            return Optional.empty();
        }
        final Map<String, String> fields = new HashMap<>();
        raw.forEach((k, v) -> fields.put(String.valueOf(k), String.valueOf(v)));
        return Optional.of(fields);
    }

    private static boolean live(final Map<String, String> fields, final Instant now) {
        final String expiresAt = fields.get(EXPIRES_AT);
        return expiresAt != null && now.toEpochMilli() < Long.parseLong(expiresAt);
    }

    private WalletTransaction toTransaction(final Map<String, String> f) {
        return new WalletTransaction(f.get(ID), decrypt(f.get(SAME_DEVICE_REQUEST)),
                decrypt(f.get(CROSS_DEVICE_REQUEST)), decrypt(f.get(RESPONSE)), f.get(REALM), f.get(ALIAS),
                f.get(STATE), f.get(BINDING), f.get(NONCE), decrypt(f.get(JWK)), f.get(DCQL),
                f.get(FLOW) == null ? null : Flow.valueOf(f.get(FLOW)), Status.valueOf(f.get(STATUS)), null,
                decrypt(f.get(IDENTITY)), f.get(FAILURE) == null ? null : WalletErrorCode.valueOf(f.get(FAILURE)),
                f.get(CREATED_AT) == null ? null : Instant.ofEpochMilli(Long.parseLong(f.get(CREATED_AT))),
                Instant.ofEpochMilli(Long.parseLong(f.get(EXPIRES_AT))));
    }

    private String now() {
        return Long.toString(clock.instant().toEpochMilli());
    }

    private String encrypt(final String value) {
        return value == null ? null : encryption.convertToDatabaseColumn(value);
    }

    private String decrypt(final String value) {
        return value == null ? null : encryption.convertToEntityAttribute(value);
    }

    /** Adds a field/value pair; a {@code null} value is left out (an absent field reads back as {@code null}). */
    private static void put(final List<String> args, final String field, final String value) {
        if (value != null) {
            args.add(field);
            args.add(value);
        }
    }
}
