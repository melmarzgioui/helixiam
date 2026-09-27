/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.service;

import io.helixiam.authorization.domain.user.UserCredentials;
import io.helixiam.authorization.security.realm.RealmContextHolder;
import io.helixiam.common.log.LogSafe;
import io.helixiam.notification.NotificationCodeIssuer;
import io.helixiam.notification.NotificationCodePolicy;
import io.helixiam.notification.Notifier;
import io.helixiam.notification.domain.NotificationRequest;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.stereotype.Component;

import java.util.Locale;
import java.util.concurrent.Executor;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

/**
 * Sends the password-reset email of an account: issues a new reset code (stored hashed) and emails the link to the
 * account's <b>stored</b> email address, never to what was typed on the reset page. Off the request thread, so a
 * request for an existing account takes as long as one for an unknown account (no enumeration by timing), and a slow
 * mail provider never delays the page.
 *
 * <p>The link goes to the stored address whether or not it is verified or has bounced, as most identity providers do:
 * it is the only address the account has, the user needs a way back in, and a bounce may have been temporary. An
 * account without an address gets nothing.
 */
@Component
public class PasswordResetMailer {

    private static final Logger LOG = LogManager.getLogger(PasswordResetMailer.class);

    private final NotificationCodeIssuer codes;
    private final Notifier notifier;
    private final Executor executor;

    @Autowired
    public PasswordResetMailer(final NotificationCodeIssuer codes, final Notifier notifier) {
        this(codes, notifier, defaultExecutor());
    }

    PasswordResetMailer(final NotificationCodeIssuer codes, final Notifier notifier, final Executor executor) {
        this.codes = codes;
        this.notifier = notifier;
        this.executor = executor;
    }

    private static Executor defaultExecutor() {
        // Bounded: a flood of reset requests queues (and the send rate caps apply), it does not spawn threads.
        final ThreadPoolExecutor pool = new ThreadPoolExecutor(1, 2, 60, TimeUnit.SECONDS,
                new LinkedBlockingQueue<>(1_000), r -> {
            final Thread t = new Thread(r, "password-reset-mail");
            t.setDaemon(true);
            return t;
        }, new ThreadPoolExecutor.DiscardOldestPolicy());
        return pool;
    }

    /** Queues the reset email of {@code account}; nothing when it has no stored address. Never throws. */
    public void send(final UserCredentials account) {
        if (account == null || account.getEmail() == null || account.getEmail().isBlank()) {
            return;
        }
        final String userId = account.getUserId();
        final String address = account.getEmail().trim();
        final String realm = RealmContextHolder.get();
        final Locale locale = LocaleContextHolder.getLocale();
        try {
            executor.execute(() -> {
                final String previousRealm = RealmContextHolder.get();
                try {
                    if (realm != null) {
                        RealmContextHolder.set(realm);
                    }
                    LocaleContextHolder.setLocale(locale);
                    final NotificationRequest request = new NotificationRequest(NotificationCodePolicy.RESET_PASSWORD);
                    request.setEmailAddress(address);
                    request.setNotificationCode(codes.issue(userId, NotificationCodePolicy.RESET_PASSWORD, false));
                    notifier.sendEmailNotification(request);
                } catch (final RuntimeException e) {
                    LOG.warn("Password-reset email for user {} not sent: {}", LogSafe.sanitize(userId),
                            LogSafe.sanitize(e.getClass().getSimpleName()));
                } finally {
                    LocaleContextHolder.resetLocaleContext();
                    if (previousRealm == null) {
                        RealmContextHolder.clear();
                    } else {
                        RealmContextHolder.set(previousRealm);
                    }
                }
            });
        } catch (final RuntimeException e) {
            LOG.warn("Password-reset email for user {} not queued: {}", LogSafe.sanitize(userId),
                    LogSafe.sanitize(e.getClass().getSimpleName()));
        }
    }
}
