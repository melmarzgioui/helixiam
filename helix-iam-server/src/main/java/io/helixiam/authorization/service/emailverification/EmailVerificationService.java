/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.service.emailverification;

import io.helixiam.authorization.domain.user.UserCredentials;
import io.helixiam.authorization.repository.UserCredentialsRepository;
import io.helixiam.authorization.repository.tenant.TenantUserRepository;
import io.helixiam.authorization.security.ratelimit.RateLimiter;
import io.helixiam.common.log.LogSafe;
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
import java.util.Arrays;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.TimeUnit;
import java.util.function.LongSupplier;
import java.util.stream.Collectors;

/**
 * C3: email verification.
 *
 * <ul>
 *   <li>A realm can require a verified email address ({@code realm_config.verify_email}, off by default): a user of
 *       that realm who has an email address that is not verified gets no tokens and is held at sign-in until the
 *       address is verified. A user with no email address is not affected by the realm setting.</li>
 *   <li>An explicit {@value #VERIFY_EMAIL} required action (set by an admin) is enforced the same way, in any realm.</li>
 *   <li>A verification link carries 256 random bits; only its SHA-256 is stored, with the address it was sent to. It
 *       expires after {@value #TTL_HOURS} hours, works once, and verifies only if the user still has that address.
 *       Verifying sets {@code email_verified} and clears the {@value #VERIFY_EMAIL} required action.</li>
 *   <li>Sending is rate limited per user ({@value #PER_USER} per 15 minutes).</li>
 * </ul>
 */
@Service
public class EmailVerificationService {

    public static final String VERIFY_EMAIL = "VERIFY_EMAIL";
    static final long TTL_HOURS = 24;
    static final int PER_USER = 5;
    private static final long WINDOW_MILLIS = TimeUnit.MINUTES.toMillis(15);
    private static final Logger LOG = LogManager.getLogger(EmailVerificationService.class);

    /** Outcome of {@link #send}. */
    public enum SendResult { SENT, NOT_FOUND, NO_EMAIL, ALREADY_VERIFIED, RATE_LIMITED, NOT_DELIVERED }

    private final JdbcTemplate jdbc;
    private final UserCredentialsRepository users;
    private final TenantUserRepository memberships;
    private final EmailVerificationSender sender;
    private final LongSupplier clock;
    private final RateLimiter perUser;
    private final SecureRandom random = new SecureRandom();

    @Autowired
    public EmailVerificationService(final JdbcTemplate jdbc, final UserCredentialsRepository users,
                                    final TenantUserRepository memberships, final EmailVerificationSender sender) {
        this(jdbc, users, memberships, sender, System::currentTimeMillis);
    }

    EmailVerificationService(final JdbcTemplate jdbc, final UserCredentialsRepository users,
                             final TenantUserRepository memberships, final EmailVerificationSender sender,
                             final LongSupplier clock) {
        this.jdbc = jdbc;
        this.users = users;
        this.memberships = memberships;
        this.sender = sender;
        this.clock = clock;
        this.perUser = new RateLimiter(PER_USER, PER_USER, WINDOW_MILLIS, 100_000, clock);
    }

    /** Whether the realm requires a verified email address before issuing tokens. */
    public boolean realmRequires(final String realmId) {
        if (realmId == null) {
            return false;
        }
        final List<Boolean> rows = jdbc.queryForList("SELECT verify_email FROM realm_config WHERE realm_id = ?",
                Boolean.class, realmId);
        return !rows.isEmpty() && Boolean.TRUE.equals(rows.get(0));
    }

    /** Switches the realm requirement; empty when the realm does not exist. */
    @Transactional // the pool runs with auto-commit off
    public Optional<Boolean> setRealmRequires(final String realmId, final boolean required) {
        final int updated = jdbc.update("UPDATE realm_config SET verify_email = ? WHERE realm_id = ?", required, realmId);
        return updated == 0 ? Optional.empty() : Optional.of(required);
    }

    /**
     * Whether {@code userId} must verify their email before tokens are issued in {@code realmId}: the address is not
     * verified and either the user has the {@value #VERIFY_EMAIL} required action, or the realm requires verification
     * and the user has an email address.
     */
    public boolean pending(final String realmId, final String userId) {
        if (userId == null) {
            return false;
        }
        return users.findByUserId(userId).map(u -> pending(realmId, u)).orElse(false);
    }

    boolean pending(final String realmId, final UserCredentials user) {
        if (user.isEmailVerified()) {
            return false;
        }
        if (hasAction(user.getRequiredActions())) {
            return true;
        }
        return user.getEmail() != null && !user.getEmail().isBlank() && realmRequires(realmId);
    }

    /** Whether the user's current address is verified. */
    public boolean verified(final String userId) {
        return userId != null && users.findByUserId(userId).map(UserCredentials::isEmailVerified).orElse(false);
    }

    /** The user's current email address, if any. */
    public Optional<String> emailOf(final String userId) {
        return userId == null ? Optional.empty()
                : users.findByUserId(userId).map(UserCredentials::getEmail).filter(e -> !e.isBlank());
    }

    /**
     * Emails a verification link to the current address of {@code userId}, a user of {@code realmId}.
     * {@code linkBase} is the realm's external base, e.g. {@code https://idp.example.com/realms/monthfold}.
     */
    @Transactional // the pool runs with auto-commit off: without a transaction the insert is rolled back
    public SendResult send(final String realmId, final String userId, final String linkBase) {
        if (realmId == null || userId == null || memberships.findByTenantIdAndUserId(realmId, userId).isEmpty()) {
            return SendResult.NOT_FOUND; // never another realm's user
        }
        final Optional<UserCredentials> found = users.findByUserId(userId);
        if (found.isEmpty()) {
            return SendResult.NOT_FOUND;
        }
        final UserCredentials user = found.get();
        final String email = user.getEmail();
        if (email == null || email.isBlank()) {
            return SendResult.NO_EMAIL;
        }
        if (user.isEmailVerified()) {
            return SendResult.ALREADY_VERIFIED;
        }
        if (!perUser.check(realmId + "|" + userId).allowed()) {
            LOG.warn("Verification email for user {} in realm {} rate limited",
                    LogSafe.sanitize(userId), LogSafe.sanitize(realmId));
            return SendResult.RATE_LIMITED;
        }
        final byte[] bytes = new byte[32];
        random.nextBytes(bytes);
        final String token = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
        final long now = clock.getAsLong();
        final String address = email.trim().toLowerCase(Locale.ROOT);
        jdbc.update("INSERT INTO email_verification_token (token_hash, realm_id, user_id, email, created_at, expires_at) "
                        + "VALUES (?, ?, ?, ?, ?, ?)", hash(token), realmId, userId, address, new Timestamp(now),
                new Timestamp(now + TimeUnit.HOURS.toMillis(TTL_HOURS)));
        final boolean delivered = sender.send(new EmailVerificationMessage(realmId, userId, address,
                linkBase + "/verify-email?token=" + token, TTL_HOURS));
        return delivered ? SendResult.SENT : SendResult.NOT_DELIVERED;
    }

    /**
     * Consumes a link of {@code realmId}: once, unexpired, and only while the user still has the address it was sent
     * to. Marks the address verified and clears the {@value #VERIFY_EMAIL} required action. Returns the user id.
     */
    @Transactional
    public Optional<String> consume(final String realmId, final String token) {
        if (realmId == null || token == null || token.isBlank() || token.length() > 128) {
            return Optional.empty();
        }
        final Timestamp now = new Timestamp(clock.getAsLong());
        final List<Map<String, Object>> rows = jdbc.queryForList("UPDATE email_verification_token SET used_at = ? "
                + "WHERE token_hash = ? AND realm_id = ? AND used_at IS NULL AND expires_at > ? "
                + "RETURNING user_id, email", now, hash(token), realmId, now);
        if (rows.isEmpty()) {
            return Optional.empty();
        }
        final String userId = String.valueOf(rows.get(0).get("user_id"));
        final String sentTo = String.valueOf(rows.get(0).get("email"));
        return users.findByUserId(userId)
                .filter(u -> u.getEmail() != null && u.getEmail().trim().equalsIgnoreCase(sentTo))
                .map(u -> {
                    u.setEmailVerified(true);
                    u.setRequiredActions(withoutAction(u.getRequiredActions()));
                    users.save(u);
                    // Verified again: a bounce recorded for this address no longer holds.
                    jdbc.update("UPDATE user_credentials SET email_bounced_at = NULL, email_bounced_address = NULL "
                            + "WHERE user_id = ? AND email_bounced_at IS NOT NULL", userId);
                    u.forgetEmailBounce();
                    LOG.info("User {} verified their email address in realm {}",
                            LogSafe.sanitize(userId), LogSafe.sanitize(realmId));
                    return userId;
                });
    }

    /** Drops a {@value #VERIFY_EMAIL} required action a user no longer needs (their address is verified). */
    @Transactional
    public void clearIfVerified(final String userId) {
        users.findByUserId(userId).filter(UserCredentials::isEmailVerified)
                .filter(u -> hasAction(u.getRequiredActions())).ifPresent(u -> {
                    u.setRequiredActions(withoutAction(u.getRequiredActions()));
                    users.save(u);
                });
    }

    public static boolean hasAction(final String csv) {
        return csv != null && Arrays.stream(csv.split(",")).map(String::trim).anyMatch(VERIFY_EMAIL::equalsIgnoreCase);
    }

    static String withoutAction(final String csv) {
        if (csv == null) {
            return null;
        }
        final String rest = Arrays.stream(csv.split(",")).map(String::trim).filter(s -> !s.isEmpty())
                .filter(s -> !VERIFY_EMAIL.equalsIgnoreCase(s)).collect(Collectors.joining(","));
        return rest.isEmpty() ? null : rest;
    }

    static String hash(final String token) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(token.getBytes(StandardCharsets.UTF_8)));
        } catch (final NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
