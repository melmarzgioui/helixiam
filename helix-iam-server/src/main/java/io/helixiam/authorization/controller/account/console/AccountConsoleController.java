/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.controller.account.console;

import io.helixiam.authorization.amqp.user.UserAdminDto;
import io.helixiam.authorization.domain.UserCredentials;
import io.helixiam.authorization.security.realm.RealmContextHolder;
import io.helixiam.authorization.security.session.AuthTimeStamper;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

import java.util.Optional;

/**
 * B1: the realm's account console, {@code /realms/{realm}/account}: the signed-in user's profile and email, password,
 * authenticator app and recovery codes, sessions, and (when the realm allows) their data and account deletion. The
 * actions are on their own pages ({@link AccountSecurityController}, {@link AccountSessionsController},
 * {@link AccountEmailController}, {@link AccountDataController}); this is the overview they return to.
 *
 * <p>{@code /me} (the former read-only profile page) redirects here, so there is one account page per realm.
 */
@Controller
@AccountConsolePage
public class AccountConsoleController {

    private final AccountOverviewService overview;

    public AccountConsoleController(final AccountOverviewService overview) {
        this.overview = overview;
    }

    @GetMapping("/account")
    public String overview(@AuthenticationPrincipal final UserCredentials principal, final HttpServletRequest request,
                           final Model model) {
        final Optional<UserAdminDto> user = member(principal);
        if (user.isEmpty()) {
            return "redirect:/login";
        }
        model.addAttribute("account", overview.build(RealmContextHolder.get(), user.get(),
                AuthTimeStamper.readSid(request), new AuthTimeStamper().read(request), org.springframework.context.i18n.LocaleContextHolder.getLocale()));
        return "account/index";
    }

    /** The former profile page: the account console is the one account page now. */
    @GetMapping("/me")
    public String me() {
        return "redirect:/account";
    }

    private Optional<UserAdminDto> member(final UserCredentials principal) {
        return principal == null ? Optional.empty() : overview.member(RealmContextHolder.get(), principal.getUserId());
    }
}
