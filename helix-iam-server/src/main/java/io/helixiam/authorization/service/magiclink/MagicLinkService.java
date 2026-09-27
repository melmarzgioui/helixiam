/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.service.magiclink;

import io.helixiam.authorization.domain.realm.RealmConfig;
import io.helixiam.authorization.domain.user.UserCredentials;
import io.helixiam.authorization.repository.UserCredentialsRepository;
import io.helixiam.authorization.repository.realm.RealmConfigRepository;
import io.helixiam.authorization.repository.tenant.TenantUserRepository;
import io.helixiam.authorization.security.ratelimit.RateLimiter;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.sql.Timestamp;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.concurrent.TimeUnit;
import java.util.function.LongSupplier;

/**
 * 1.0 item 6: passwordless sign-in by emailed link.
 *
 * <ul>
 *   <li>Opt-in per realm ({@code realm_config.magic_link_enabled}).</li>
 *   <li>A link carries 256 random bits; only its SHA-256 is stored ({@code magic_link_token}). It expires after
 *       15 minutes and is consumed atomically, so it signs in exactly once.</li>
 *   <li>Requests are rate limited per email address (5 per 15 minutes) and per client IP (20 per 15 minutes).</li>
 *   <li>A request for an unknown, disabled or locked account, or one over the limit, sends nothing — and the
 *       caller shows the same answer either way, so addresses cannot be enumerated.</li>
 * </ul>
 */
@Service
public class MagicLinkService {

    static final long TTL_MINUTES = 15;
    static final int PER_EMAIL = 5;
    static final int PER_IP = 20;
    private static final long WINDOW_MILLIS = TimeUnit.MINUTES.toMillis(15);
    private static final Logger LOG = LogManager.getLogger(MagicLinkService.class);

    private final JdbcTemplate jdbc;
    private final RealmConfigRepository realms;
    private final UserCredentialsRepository users;
    private final TenantUserRepository memberships;
    private final MagicLinkSender sender;
    private final LongSupplier clock;
    private final RateLimiter perEmail;
    private final RateLimiter perIp;
    private final SecureRandom random = new SecureRandom();

    @Autowired
    public MagicLinkService(final JdbcTemplate jdbc, final RealmConfigRepository realms, final UserCredentialsRepository users,
                            final TenantUserRepository memberships, final MagicLinkSender sender) {
        this(jdbc, realms, users, memberships, sender, System::currentTimeMillis);
    }

    MagicLinkService(final JdbcTemplate jdbc, final RealmConfigRepository realms, final UserCredentialsRepository users,
                     final TenantUserRepository memberships, final MagicLinkSender sender, final LongSupplier clock) {
        this.jdbc = jdbc;
        this.realms = realms;
        this.users = users;
        this.memberships = memberships;
        this.sender = sender;
        this.clock = clock;
        this.perEmail = new RateLimiter(PER_EMAIL, PER_EMAIL, WINDOW_MILLIS, 100_000, clock);
        this.perIp = new RateLimiter(PER_IP, PER_IP, WINDOW_MILLIS, 100_000, clock);
    }

    public boolean enabled(final String realmId) {
        return realmId != null && realms.findById(realmId).map(RealmConfig::isMagicLinkEnabled).orElse(false);
    }

    @Transactional
    public Optional<Boolean> setEnabled(final String realmId, final boolean enabled) {
        return realms.findById(realmId).map(cfg -> {
            cfg.setMagicLinkEnabled(enabled);
            realms.save(cfg);
            return enabled;
        });
    }

    /**
     * Emails a sign-in link to {@code email} if it belongs to an active account of the realm and the limits allow.
     * {@code linkBase} is the realm's external base, e.g. {@code https://idp.example.com/realms/monthfold}.
     */
    @Transactional // the pool runs with auto-commit off: without a transaction the insert is rolled back
    public void request(final String realmId, final String email, final String clientIp, final String linkBase) {
        if (!enabled(realmId) || email == null || email.isBlank()) {
            return;
        }
        final String address = email.trim().toLowerCase(Locale.ROOT);
        if (!perIp.check(realmId + "|" + clientIp).allowed() || !perEmail.check(realmId + "|" + address).allowed()) {
            LOG.warn("Magic-link request rate limited in realm {} (ip {})", realmId, clientIp);
            return;
        }
        final Optional<UserCredentials> user = users.findByRealmIdAndEmail(realmId, address)
                .filter(u -> memberships.findByTenantIdAndUserId(realmId, u.getUserId()).isPresent())
                .filter(u -> !u.isDisabled() && !u.isLocked()); // same meaning as the admin API
        if (user.isEmpty()) {
            return;
        }
        final byte[] bytes = new byte[32];
        random.nextBytes(bytes);
        final String token = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
        final long now = clock.getAsLong();
        jdbc.update("INSERT INTO magic_link_token (token_hash, realm_id, user_id, created_at, expires_at) VALUES (?, ?, ?, ?, ?)",
                hash(token), realmId, user.get().getUserId(), new Timestamp(now),
                new Timestamp(now + TimeUnit.MINUTES.toMillis(TTL_MINUTES)));
        sender.send(new MagicLinkMessage(realmId, user.get().getUserId(), address,
                linkBase + "/login/magic/verify?token=" + token, TTL_MINUTES));
    }

    /** Consumes a link: the user id it signs in, once, if it is valid, unexpired and of this realm. */
    @Transactional
    public Optional<String> consume(final String realmId, final String token) {
        if (realmId == null || token == null || token.isBlank() || token.length() > 128) {
            return Optional.empty();
        }
        final Timestamp now = new Timestamp(clock.getAsLong());
        final List<String> userIds = jdbc.queryForList("UPDATE magic_link_token SET used_at = ? WHERE token_hash = ? "
                + "AND realm_id = ? AND used_at IS NULL AND expires_at > ? RETURNING user_id", String.class,
                now, hash(token), realmId, now);
        return userIds.stream().findFirst();
    }

    static String hash(final String token) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(token.getBytes(StandardCharsets.UTF_8)));
        } catch (final NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
