/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.messaging;

import io.helixiam.authorization.security.realm.RealmContextHolder;
import io.helixiam.common.log.LogSafe;
import io.helixiam.notification.delivery.spi.EmailComposer;
import io.helixiam.notification.domain.NotificationRequest;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.MessageSource;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.util.HtmlUtils;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Locale;
import java.util.Optional;

/**
 * The account emails of a realm's self-service pages, rendered in the language the user was using and under the
 * realm's (or the organization in context's) brand, in the shared {@link EmailLayout}:
 * <ul>
 *   <li>{@code USER_SIGNUP} (item A7): a button linking to {@code /realms/{realm}/register/verify/{code}}, the code
 *       itself, and a link to the page where it can be typed ({@code /realms/{realm}/register/verify});</li>
 *   <li>{@code USER_RESET_PASSWORD}: a button linking to {@code /realms/{realm}/reset/password/{code}} and the code.</li>
 * </ul>
 * Links are absolute on {@code idp.base.url} (never the request's host: a forged {@code Host} header must not
 * send a user a valid code on another domain); without it the email carries the code only. Every value is
 * HTML-escaped. Other notification types, and notifications outside a realm, are left to the plain-text fallback.
 */
@Component
public class AccountEmails implements EmailComposer {

    static final String SIGNUP = "USER_SIGNUP";
    static final String RESET = "USER_RESET_PASSWORD";
    private static final Logger LOG = LogManager.getLogger(AccountEmails.class);

    private final MessageSource messages;
    private final EmailBrandingSource branding;
    private final String idpBaseUrl;

    public AccountEmails(final MessageSource messages, final EmailBrandingSource branding,
                         @Value("${idp.base.url:}") final String idpBaseUrl) {
        this.messages = messages;
        this.branding = branding;
        this.idpBaseUrl = idpBaseUrl == null ? "" : idpBaseUrl.trim().replaceAll("/+$", "");
    }

    @Override
    public Optional<ComposedEmail> compose(final NotificationRequest notification) {
        final String type = notification == null ? null : notification.getType();
        final String realm = RealmContextHolder.get();
        final String code = notification == null || notification.getNotificationCode() == null ? null
                : notification.getNotificationCode().getCode();
        if (realm == null || code == null || !(SIGNUP.equals(type) || RESET.equals(type))) {
            return Optional.empty();
        }
        return Optional.of(compose(type, realm, code, LocaleContextHolder.getLocale(), branding.brandingFor(realm)));
    }

    /** The email for {@code type} (package-visible for tests). */
    ComposedEmail compose(final String type, final String realm, final String code, final Locale locale,
                          final EmailBranding brand) {
        final EmailBranding b = brand == null ? EmailBranding.helixIam() : brand;
        final String realmUrl = idpBaseUrl.isEmpty() ? null : idpBaseUrl + "/realms/" + enc(realm);
        if (realmUrl == null) {
            LOG.warn("idp.base.url (IDP_BASE_URL) is not configured: the {} email for realm {} carries the code only",
                    type, LogSafe.sanitize(realm));
        }
        final boolean signup = SIGNUP.equals(type);
        final String prefix = signup ? "email.verify." : "email.reset.";
        final String link = realmUrl == null ? null
                : realmUrl + (signup ? "/register/verify/" : "/reset/password/") + enc(code);
        final String subject = text(prefix + "subject", locale, b.name());

        final StringBuilder body = new StringBuilder();
        body.append("<p>").append(esc(text(prefix + "intro", locale, b.name()))).append("</p>\n");
        if (link != null) {
            body.append("<p><a href=\"").append(esc(link)).append("\" data-button>")
                    .append(esc(text(prefix + "button", locale))).append("</a></p>\n");
        }
        body.append("<p>").append(esc(text(prefix + "code", locale))).append("<br><strong style=\"font-family:")
                .append(EmailLayout.MONO).append(";font-size:16px;letter-spacing:1px;word-break:break-all;\">")
                .append(esc(code)).append("</strong>");
        if (signup && realmUrl != null) {
            body.append("<br><a href=\"").append(esc(realmUrl + "/register/verify")).append("\" style=\"color:")
                    .append(b.color()).append(";\">").append(esc(text("email.verify.codePage", locale))).append("</a>");
        }
        body.append("</p>\n");
        if (link != null) {
            body.append("<p style=\"color:").append(b.inkMuted()).append(";font-size:13px;\">")
                    .append(esc(text("email.linkFallback", locale))).append("<br><a href=\"").append(esc(link))
                    .append("\" style=\"color:").append(b.inkMuted()).append(";word-break:break-all;\">")
                    .append(esc(link)).append("</a></p>\n");
        }
        body.append("<p style=\"color:").append(b.inkMuted()).append(";font-size:13px;\">")
                .append(esc(text(prefix + "ignore", locale))).append("</p>");
        return new ComposedEmail(subject, EmailLayout.wrap(b, subject, body.toString(), locale), true);
    }

    private String text(final String key, final Locale locale, final Object... args) {
        return messages.getMessage(key, args, key, locale == null ? Locale.ENGLISH : locale);
    }

    private static String esc(final String value) {
        return HtmlUtils.htmlEscape(value == null ? "" : value, "UTF-8");
    }

    private static String enc(final String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8).replace("+", "%20");
    }
}
