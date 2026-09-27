/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.controller.account.console;

import io.helixiam.authorization.amqp.user.UserAdminDto;
import io.helixiam.authorization.amqp.user.UserAdminPublisher;
import io.helixiam.authorization.amqp.user.UserAdminRef;
import io.helixiam.authorization.repository.UserCredentialsRepository;
import io.helixiam.authorization.repository.mfa.RecoveryCodeRepository;
import io.helixiam.authorization.service.account.AccountConsoleSettings;
import io.helixiam.authorization.service.account.AccountConsoleSettingsService;
import io.helixiam.authorization.service.mfa.MfaPolicyService;
import io.helixiam.authorization.service.mfa.TotpService;
import io.helixiam.authorization.session.AccountSessionService;
import io.helixiam.authorization.session.SsoSessionView;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;

/** B1: builds the account console's overview ({@link AccountOverview}) for the signed-in user of a realm. */
@Service
public class AccountOverviewService {

    private final UserAdminPublisher users;
    private final UserCredentialsRepository credentials;
    private final RecoveryCodeRepository recoveryCodes;
    private final TotpService totp;
    private final MfaPolicyService mfaPolicy;
    private final AccountConsoleSettingsService settings;
    private final AccountSessionService sessions;

    public AccountOverviewService(final UserAdminPublisher users, final UserCredentialsRepository credentials,
                                  final RecoveryCodeRepository recoveryCodes, final TotpService totp,
                                  final MfaPolicyService mfaPolicy, final AccountConsoleSettingsService settings,
                                  final AccountSessionService sessions) {
        this.users = users;
        this.credentials = credentials;
        this.recoveryCodes = recoveryCodes;
        this.totp = totp;
        this.mfaPolicy = mfaPolicy;
        this.settings = settings;
        this.sessions = sessions;
    }

    /** The user as a member of {@code realm}; empty when they are not (a session from another realm). */
    public Optional<UserAdminDto> member(final String realm, final String userId) {
        if (realm == null || userId == null) {
            return Optional.empty();
        }
        return Optional.ofNullable(users.get(new UserAdminRef(realm, userId)));
    }

    public AccountOverview build(final String realm, final UserAdminDto user, final String currentSid,
                                 final Long authTime, final Locale locale) {
        final Map<String, String> a = user.attributes() == null ? Map.of() : user.attributes();
        final boolean verified = credentials.findByUserId(user.userId()).map(u -> u.isEmailVerified()).orElse(false);
        final AccountOverview.Profile profile = new AccountOverview.Profile(blank(user.username()), blank(user.email()),
                verified, blank(a.get("given_name")), blank(a.get("family_name")), blank(a.get("phone_number")));
        return new AccountOverview(profile, twoStep(realm, user.userId()),
                sessionRows(realm, user.userId(), currentSid, authTime, locale),
                settings.get(realm).dataExport(), settings.get(realm).accountDeletion());
    }

    /** The two-step verification state of the user. */
    public AccountOverview.TwoStep twoStep(final String realm, final String userId) {
        final boolean required = mfaPolicy.required(realm);
        final AccountConsoleSettings s = settings.get(realm);
        return new AccountOverview.TwoStep(totp.isEnrolled(userId), required, s.authenticatorRemoval() && !required,
                recoveryCodes.findAllByUserIdAndUsedFalse(userId).size());
    }

    private List<AccountOverview.SessionRow> sessionRows(final String realm, final String userId, final String currentSid,
                                                         final Long authTime, final Locale locale) {
        final List<AccountOverview.SessionRow> rows = new ArrayList<>();
        AccountOverview.SessionRow current = new AccountOverview.SessionRow(true,
                authTime == null ? null : format(Instant.ofEpochSecond(authTime), locale), List.of());
        for (final SsoSessionView s : sessions.listSessions(realm, userId)) {
            final List<String> apps = s.clients().stream().map(SsoSessionView.ClientView::clientId).distinct().toList();
            if (currentSid != null && currentSid.equals(s.ssoSessionId())) {
                current = new AccountOverview.SessionRow(true, current.signedIn() != null ? current.signedIn()
                        : format(s.issuedAt(), locale), apps);
            } else {
                rows.add(new AccountOverview.SessionRow(false, format(s.issuedAt(), locale), apps));
            }
        }
        rows.add(0, current);
        return rows;
    }

    static String format(final Instant instant, final Locale locale) {
        return instant == null ? null : DateTimeFormatter.ofPattern("d MMM yyyy, HH:mm 'UTC'",
                locale == null ? Locale.ENGLISH : locale).withZone(ZoneOffset.UTC).format(instant);
    }

    private static String blank(final String v) {
        return v == null || v.isBlank() ? null : v;
    }
}
