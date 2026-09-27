/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.service.account;

import io.helixiam.authorization.domain.user.UserCredentials;
import io.helixiam.authorization.messaging.MessageVariables;
import io.helixiam.authorization.messaging.MessagingService;
import io.helixiam.authorization.repository.UserCredentialsRepository;
import io.helixiam.authorization.service.UserInfoService;
import io.helixiam.authorization.service.messaging.MessagingAdminService;
import io.helixiam.common.log.LogSafe;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataIntegrityViolationException;
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
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.TimeUnit;
import java.util.function.LongSupplier;

/**
 * B1: changing the email address in the account console.
 * <ul>
 *   <li>The new address is stored at once (lower-cased, unique in the realm) and is <b>not verified</b> until the user
 *       opens the link sent to it; relying parties see {@code email_verified=false} meanwhile.</li>
 *   <li>The link carries 256 random bits; only its SHA-256 is stored ({@code email_change_token}). It works once, for
 *       24 hours, only in its realm, and only while the address it was sent to is still the account's address. A new
 *       change voids the earlier links.</li>
 *   <li>The previous address gets a notice that the address changed (it does not name the new one).</li>
 *   <li>Emails go through the realm's email provider and templates ({@code email-change-verify},
 *       {@code email-changed-notice}); without a provider nothing is sent and a warning is logged, never the link.</li>
 * </ul>
 */
@Service
public class EmailChangeService {

    static final long TTL_HOURS = 24;
    static final int MAX_LENGTH = 254;
    private static final Logger LOG = LogManager.getLogger(EmailChangeService.class);

    /** The outcome of a change request. */
    public enum Outcome { CHANGED, INVALID, TAKEN, SAME, UNKNOWN_USER }

    private final JdbcTemplate jdbc;
    private final UserCredentialsRepository users;
    private final MessagingService messaging;
    private final MessagingAdminService templates;
    private final UserInfoService userInfo;
    private final LongSupplier clock;
    private final SecureRandom random = new SecureRandom();

    @Autowired
    public EmailChangeService(final JdbcTemplate jdbc, final UserCredentialsRepository users,
                              final MessagingService messaging, final MessagingAdminService templates,
                              final UserInfoService userInfo) {
        this(jdbc, users, messaging, templates, userInfo, System::currentTimeMillis);
    }

    EmailChangeService(final JdbcTemplate jdbc, final UserCredentialsRepository users, final MessagingService messaging,
                       final MessagingAdminService templates, final UserInfoService userInfo, final LongSupplier clock) {
        this.jdbc = jdbc;
        this.users = users;
        this.messaging = messaging;
        this.templates = templates;
        this.userInfo = userInfo;
        this.clock = clock;
    }

    /**
     * {@code local@domain} with exactly one {@code @}, no whitespace, a non-empty local part and a dot inside the
     * domain (not its first or last character) — what {@code ^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$} accepted, checked in one
     * pass: that regex backtracks polynomially on a domain of many dots (CodeQL #254).
     */
    static boolean isPlausible(final String email) {
        final int at = email.indexOf('@');
        if (at < 1 || email.indexOf('@', at + 1) >= 0) {
            return false;
        }
        for (int i = 0; i < email.length(); i++) {
            final char c = email.charAt(i);
            if (c == ' ' || c == '\t' || c == '\n' || c == '\u000B' || c == '\f' || c == '\r') {
                return false;
            }
        }
        final int dot = email.indexOf('.', at + 2); // the domain's first character may not be the separating dot
        return dot >= 0 && dot < email.length() - 1;
    }

    /** The address as stored: trimmed and lower-cased; null when it is not a plausible email address. */
    public static String normalise(final String email) {
        if (email == null) {
            return null;
        }
        final String trimmed = email.trim().toLowerCase(Locale.ROOT);
        return trimmed.length() <= MAX_LENGTH && isPlausible(trimmed) ? trimmed : null;
    }

    /**
     * Changes the user's address to {@code newEmail} (unverified) and emails the confirmation link, built on
     * {@code linkBase} (the realm's external base, e.g. {@code https://idp.example.com/realms/acme}).
     */
    @Transactional
    public Outcome change(final String realmId, final String userId, final String newEmail, final String linkBase) {
        final String address = normalise(newEmail);
        if (address == null) {
            return Outcome.INVALID;
        }
        final UserCredentials user = users.findByUserId(userId).orElse(null);
        if (user == null) {
            return Outcome.UNKNOWN_USER;
        }
        final String previous = user.getEmail();
        if (address.equalsIgnoreCase(previous == null ? "" : previous)) {
            return Outcome.SAME;
        }
        if (users.findByRealmIdAndEmail(realmId, address).filter(u -> !u.getUserId().equals(userId)).isPresent()) {
            return Outcome.TAKEN;
        }
        user.setEmail(address);
        user.setEmailVerified(false);
        try {
            users.saveAndFlush(user);
        } catch (final DataIntegrityViolationException e) {
            return Outcome.TAKEN; // taken by a concurrent change
        }
        sendLink(realmId, userId, address, linkBase);
        if (previous != null && !previous.isBlank()) {
            send(realmId, userId, previous, MessagingAdminService.EMAIL_CHANGED_NOTICE, Map.of());
        }
        return Outcome.CHANGED;
    }

    /**
     * Voids the user's earlier links and emails a new confirmation link for {@code address} (also used when the email
     * address is changed through the account API).
     */
    @Transactional
    public void sendLink(final String realmId, final String userId, final String address, final String linkBase) {
        final long now = clock.getAsLong();
        jdbc.update("UPDATE email_change_token SET used_at = ? WHERE user_id = ? AND used_at IS NULL",
                new Timestamp(now), userId);
        final byte[] bytes = new byte[32];
        random.nextBytes(bytes);
        final String token = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
        jdbc.update("INSERT INTO email_change_token (token_hash, realm_id, user_id, email, created_at, expires_at) "
                        + "VALUES (?, ?, ?, ?, ?, ?)", hash(token), realmId, userId, address, new Timestamp(now),
                new Timestamp(now + TimeUnit.HOURS.toMillis(TTL_HOURS)));
        send(realmId, userId, address, MessagingAdminService.EMAIL_CHANGE_VERIFY,
                Map.of("link", linkBase + "/account/email/verify?token=" + token, "ttl", io.helixiam.authorization.messaging.DefaultMessageTemplates.hours(TTL_HOURS, org.springframework.context.i18n.LocaleContextHolder.getLocale())));
    }

    /**
     * Consumes a confirmation link: marks the address verified, once, if the link is valid, unexpired, of this realm
     * and the address is still the account's. Returns the user id and address it confirmed.
     */
    @Transactional
    public Optional<Confirmed> confirm(final String realmId, final String token) {
        if (realmId == null || token == null || token.isBlank() || token.length() > 128) {
            return Optional.empty();
        }
        final Timestamp now = new Timestamp(clock.getAsLong());
        final List<Confirmed> rows = jdbc.query("UPDATE email_change_token SET used_at = ? WHERE token_hash = ? "
                        + "AND realm_id = ? AND used_at IS NULL AND expires_at > ? RETURNING user_id, email",
                (rs, i) -> new Confirmed(rs.getString(1), rs.getString(2)), now, hash(token), realmId, now);
        if (rows.isEmpty()) {
            return Optional.empty();
        }
        final Confirmed confirmed = rows.get(0);
        final int updated = jdbc.update("UPDATE user_credentials SET email_verified = true WHERE user_id = ? "
                + "AND lower(email) = lower(?)", confirmed.userId(), confirmed.email());
        return updated == 1 ? Optional.of(confirmed) : Optional.empty();
    }

    /** A confirmed address. */
    public record Confirmed(String userId, String email) {
    }

    private void send(final String realmId, final String userId, final String to, final String template,
                      final Map<String, String> extra) {
        try {
            templates.ensureDefaultTemplate(realmId, template);
            final Map<String, String> profile = profile(userId);
            final Map<String, String> vars = new LinkedHashMap<>(extra);
            vars.put("realm", realmId);
            vars.put("user", firstNonBlank(profile.get("name"), profile.get("given_name"), "there"));
            if (!messaging.sendEmail(realmId, to, template, MessageVariables.withUserClaims(vars, profile))) {
                LOG.warn("Email {} for user {} NOT sent: realm {} has no email provider configured",
                        template, LogSafe.sanitize(userId), LogSafe.sanitize(realmId));
            }
        } catch (final RuntimeException e) {
            LOG.warn("Email {} for user {} NOT sent: {}", template, LogSafe.sanitize(userId),
                    LogSafe.sanitize(e.getMessage()));
        }
    }

    private Map<String, String> profile(final String userId) {
        try {
            final Map<String, String> p = userInfo.getOidcClaimProfile(userId);
            return p == null ? Map.of() : p;
        } catch (final RuntimeException e) {
            return Map.of();
        }
    }

    private static String firstNonBlank(final String... values) {
        for (final String v : values) {
            if (v != null && !v.isBlank()) {
                return v;
            }
        }
        return null;
    }

    static String hash(final String token) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(token.getBytes(StandardCharsets.UTF_8)));
        } catch (final NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
