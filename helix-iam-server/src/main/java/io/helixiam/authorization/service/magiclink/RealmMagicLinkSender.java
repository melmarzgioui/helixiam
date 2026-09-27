/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.service.magiclink;

import io.helixiam.authorization.messaging.MessageVariables;
import io.helixiam.authorization.messaging.MessagingService;
import io.helixiam.authorization.service.UserInfoService;
import io.helixiam.common.log.LogSafe;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.stereotype.Component;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Emails the sign-in link through the realm's configured email provider (SMTP or HTTP), rendering the realm's
 * {@code magic-link-email} template ({@code {{link}}}, {@code {{ttl}}}, {@code {{realm}}}, {@code {{user}}} and
 * {@code {{user.<claim>}}}). Without a configured provider nothing is sent and a warning is logged — the link is
 * never written to the log.
 */
@Component
public class RealmMagicLinkSender implements MagicLinkSender {

    private static final Logger LOG = LogManager.getLogger(RealmMagicLinkSender.class);

    private final MessagingService messaging;
    private final UserInfoService userInfo;

    public RealmMagicLinkSender(final MessagingService messaging, final UserInfoService userInfo) {
        this.messaging = messaging;
        this.userInfo = userInfo;
    }

    @Override
    public void send(final MagicLinkMessage message) {
        try {
            final Map<String, String> profile = safeProfile(message.userId());
            final Map<String, String> base = new LinkedHashMap<>();
            base.put("realm", message.realmId());
            base.put("link", message.link());
            base.put("ttl", io.helixiam.authorization.messaging.DefaultMessageTemplates.minutes(message.ttlMinutes(), org.springframework.context.i18n.LocaleContextHolder.getLocale()));
            base.put("user", firstNonBlank(profile.get("name"), profile.get("given_name"), message.email(), "there"));
            // Never retried after the link expires.
            if (messaging.sendEmail(message.realmId(), message.email(), "magic-link-email",
                    MessageVariables.withUserClaims(base, profile), java.time.Duration.ofMinutes(message.ttlMinutes()))) {
                LOG.info("Magic link emailed to user {} in realm {}",
                        LogSafe.sanitize(message.userId()), LogSafe.sanitize(message.realmId()));
                return;
            }
            LOG.warn("Magic link for user {} NOT sent: realm {} has no email provider configured",
                    LogSafe.sanitize(message.userId()), LogSafe.sanitize(message.realmId()));
        } catch (final RuntimeException e) {
            LOG.warn("Magic link for user {} NOT sent: {}", message.userId(), e.getMessage());
        }
    }

    private Map<String, String> safeProfile(final String userId) {
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
}
