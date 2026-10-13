/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.wallet;

import io.helixiam.authorization.domain.user.UserCredentials;
import io.helixiam.authorization.messaging.DefaultMessageTemplates;
import io.helixiam.authorization.messaging.MessagingService;
import io.helixiam.authorization.repository.UserCredentialsRepository;
import io.helixiam.authorization.service.messaging.MessagingAdminService;
import io.helixiam.common.log.LogSafe;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.stereotype.Component;

import java.util.Map;

/**
 * Production readiness item 4: the "wallet linked" security notice. When an EU Digital Identity Wallet is linked to an
 * account (the account console's link flow, or the upgrade path that adds the administrative-number link at sign-in),
 * the account's email address gets: "An EU Digital Identity Wallet was linked to your account. If this wasn't you,
 * unlink it and change your password." It is the user's chance to notice a link they did not make (the documented
 * QR-relay and linking-CSRF limits, {@code docs/eudi-wallet.md} §6.3).
 *
 * <ul>
 *   <li>Sent like the other account notices ({@code email-changed-notice}): the realm's email provider and its
 *       {@value #TEMPLATE} template, which the realm can reword in the console (Messaging → Templates). Without an
 *       email provider nothing is sent and a warning is logged.</li>
 *   <li>Carries only the realm name. Never the wallet subject (or its hash), never a PID value, never the user's
 *       profile (a JIT account's profile came from the PID).</li>
 *   <li>Nothing is sent when the account has no email address on file, or belongs to another realm.</li>
 *   <li>Best effort: a failure is logged and never fails the link.</li>
 * </ul>
 */
@Component
public class WalletLinkedNotice {

    /** The message template key. */
    public static final String TEMPLATE = DefaultMessageTemplates.WALLET_LINKED_NOTICE;

    private static final Logger LOG = LogManager.getLogger(WalletLinkedNotice.class);

    private final UserCredentialsRepository users;
    private final MessagingService messaging;
    private final MessagingAdminService templates;

    public WalletLinkedNotice(final UserCredentialsRepository users, final MessagingService messaging,
                              final MessagingAdminService templates) {
        this.users = users;
        this.messaging = messaging;
        this.templates = templates;
    }

    /** Emails the notice to {@code userId} of {@code realmId}, if the account has an email address. Never throws. */
    public void send(final String realmId, final String userId) {
        try {
            final UserCredentials user = users.findByUserId(userId).orElse(null);
            if (user == null || realmId == null || !realmId.equals(user.getRealmId())) {
                return;
            }
            final String email = user.getEmail();
            if (email == null || email.isBlank()) {
                LOG.info("wallet: linked-wallet notice not sent, no email address on file: realm={} user={}",
                        LogSafe.sanitize(realmId), LogSafe.sanitize(userId));
                return;
            }
            templates.ensureDefaultTemplate(realmId, TEMPLATE);
            if (!messaging.sendEmail(realmId, email, TEMPLATE, Map.of("realm", realmId))) {
                LOG.warn("wallet: linked-wallet notice for user {} NOT sent: realm {} has no email provider configured",
                        LogSafe.sanitize(userId), LogSafe.sanitize(realmId));
            }
        } catch (final RuntimeException e) {
            LOG.warn("wallet: linked-wallet notice for user {} NOT sent: {}", LogSafe.sanitize(userId),
                    e.getClass().getSimpleName());
        }
    }
}
