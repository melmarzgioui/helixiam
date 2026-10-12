/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.wallet;

import io.helixiam.common.log.LogSafe;
import io.helixiam.common.startup.DeploymentProfile;
import io.helixiam.persistence.security.AttributeEncryption;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.TransactionTemplate;

import java.security.SecureRandom;
import java.util.Base64;
import java.util.List;

/**
 * The per-realm pepper of the wallet subject HMAC ({@link WalletSubjectResolver}, spec §8.2: "hash with a per-realm
 * secret pepper ... stored the same way other realm secrets are stored"). Helix has no generic realm-secret store, so
 * this follows the Task 5 verifier-key precedent: its own table ({@code realm_wallet_pepper}, Flyway V77 and
 * schema.sql), JDBC, the value encrypted at rest with {@code DB_ENCRYPTION} ({@link AttributeEncryption}, AES-GCM).
 *
 * <ul>
 *   <li><b>Lazy:</b> 256 random bits ({@link SecureRandom}) are created on a realm's first wallet subject.</li>
 *   <li><b>Race-safe:</b> creation is {@code INSERT ... ON CONFLICT (realm_id) DO NOTHING} in its own transaction,
 *       then a re-read; concurrent first uses (threads or replicas) all end up with the one row that won.</li>
 *   <li><b>Encrypted:</b> without {@code DB_ENCRYPTION} creation is refused ({@link IllegalStateException}) unless the
 *       {@code dev} profile is active ({@link DeploymentProfile}), where it is stored in plaintext with a warning.</li>
 *   <li><b>Dev plaintext fails closed:</b> a pepper created in plaintext under {@code dev} (no {@code DB_ENCRYPTION})
 *       is refused once {@code DB_ENCRYPTION} is set, and so is a pepper encrypted under a {@code DB_ENCRYPTION} key
 *       that has since changed or rotated ({@link AttributeEncryption} would hand the undecryptable value back as-is,
 *       so it is detected explicitly): {@link #pepper} throws {@link IllegalStateException} and
 *       wallet sign-in fails for that realm. It is never silently replaced (that would orphan every wallet link); an
 *       operator who promotes such a database deletes the realm's {@code realm_wallet_pepper} row, accepting that its
 *       wallet links and admin-number JIT links stop matching.</li>
 *   <li><b>Immutable and private:</b> never rotated (rotating it would orphan every wallet link and JIT account of the
 *       realm), never logged, never part of a realm export (the export reads only its own slices).</li>
 * </ul>
 */
@Component
public class RealmWalletPepper {

    private static final Logger LOG = LogManager.getLogger(RealmWalletPepper.class);
    private static final int PEPPER_BYTES = 32;
    private static final String ENCRYPTION_PROBE = "helix-encryption-probe";

    private final JdbcTemplate jdbc;
    private final TransactionTemplate tx;
    private final TransactionTemplate readTx;
    private final AttributeEncryption encryption;
    private final DeploymentProfile profile;
    private final boolean encrypted;
    private final SecureRandom random = new SecureRandom();

    @Autowired
    public RealmWalletPepper(final JdbcTemplate jdbc, final PlatformTransactionManager transactions,
                             @Value("${database.encryption:#{null}}") final String encryptionKey,
                             final DeploymentProfile profile) {
        this(jdbc, transactions, new AttributeEncryption(encryptionKey), profile);
    }

    public RealmWalletPepper(final JdbcTemplate jdbc, final PlatformTransactionManager transactions,
                             final AttributeEncryption encryption, final DeploymentProfile profile) {
        this.jdbc = jdbc;
        // The pool has auto-commit off: the insert commits in its own transaction.
        this.tx = new TransactionTemplate(transactions);
        this.tx.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRES_NEW);
        this.readTx = new TransactionTemplate(transactions);
        this.readTx.setReadOnly(true);
        this.encryption = encryption;
        this.profile = profile;
        // AttributeEncryption without a key passes values through unchanged.
        this.encrypted = !ENCRYPTION_PROBE.equals(encryption.convertToDatabaseColumn(ENCRYPTION_PROBE));
    }

    /**
     * The realm's pepper (32 bytes), created on first use.
     *
     * @throws IllegalArgumentException for a blank realm
     * @throws IllegalStateException    when it must be created but {@code DB_ENCRYPTION} is not set outside dev, or
     *                                  the stored value is corrupt
     */
    public byte[] pepper(final String realmId) {
        if (realmId == null || realmId.isBlank()) {
            throw new IllegalArgumentException("A realm is required");
        }
        final byte[] existing = read(realmId);
        if (existing != null) {
            return existing;
        }
        if (!encrypted) {
            if (!profile.isDev()) {
                throw new IllegalStateException("Database encryption is not configured: set DB_ENCRYPTION before "
                        + "using EUDI Wallet sign-in (the wallet subject pepper must be stored encrypted)");
            }
            LOG.warn("wallet: creating the subject pepper of realm {} WITHOUT DB_ENCRYPTION (dev profile only)",
                    LogSafe.sanitize(realmId));
        }
        final byte[] fresh = new byte[PEPPER_BYTES];
        random.nextBytes(fresh);
        final String column = encryption.convertToDatabaseColumn(Base64.getEncoder().encodeToString(fresh));
        final Integer inserted = tx.execute(s -> jdbc.update(
                "INSERT INTO realm_wallet_pepper (realm_id, pepper) VALUES (?, ?) ON CONFLICT (realm_id) DO NOTHING",
                realmId, column));
        if (inserted != null && inserted == 1) {
            LOG.info("wallet: created the subject pepper of realm {}", LogSafe.sanitize(realmId));
        }
        final byte[] stored = read(realmId);
        if (stored == null) {
            throw new IllegalStateException("The wallet subject pepper could not be stored");
        }
        return stored;
    }

    private byte[] read(final String realmId) {
        final List<String> rows = readTx.execute(s -> jdbc.queryForList(
                "SELECT pepper FROM realm_wallet_pepper WHERE realm_id = ?", String.class, realmId));
        if (rows == null || rows.isEmpty()) {
            return null;
        }
        final String column = rows.get(0);
        String plain;
        try {
            plain = encryption.convertToEntityAttribute(column);
        } catch (final RuntimeException e) {
            plain = column; // the converter refuses what it cannot decrypt (since the security merge): same case below
        }
        if (encrypted && column.equals(plain)) {
            // A plaintext (dev) pepper, or one encrypted under a DB_ENCRYPTION key that has since changed: the converter
            // refuses it (older converters handed it back as-is, which this guard still catches). Either way: fail
            // closed, naming both causes for the operator.
            throw new IllegalStateException("The stored wallet subject pepper cannot be decrypted with the current "
                    + "DB_ENCRYPTION key: it was either created without DB_ENCRYPTION (dev), or DB_ENCRYPTION has "
                    + "changed or rotated since; refusing to use it");
        }
        final byte[] pepper;
        try {
            pepper = Base64.getDecoder().decode(plain);
        } catch (final RuntimeException e) {
            throw new IllegalStateException("The stored wallet subject pepper cannot be read");
        }
        if (pepper.length != PEPPER_BYTES) {
            throw new IllegalStateException("The stored wallet subject pepper is corrupt");
        }
        return pepper;
    }
}
