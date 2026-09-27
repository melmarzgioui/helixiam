/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.controller.account.console;

import io.helixiam.authorization.amqp.user.UserAdminDto;
import io.helixiam.authorization.domain.UserCredentials;
import io.helixiam.authorization.security.realm.RealmContextHolder;
import io.helixiam.authorization.service.account.AccountStepUp;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

import java.util.Locale;
import java.util.Optional;

/**
 * B1: what the account console's action controllers share — who the signed-in user is in this realm, the step-up
 * redirect, and ending the session when the account got locked.
 */
@Component
public class AccountConsoleSupport {

    /** Where the console sends a browser whose session was ended because the account is now locked. */
    static final String LOCKED = "redirect:/login?error=accountLocked";

    /** The pages a re-authentication returns to ({@code ?next=}); anything else returns to the overview. */
    enum Next {
        AUTHENTICATOR("/account/authenticator"),
        AUTHENTICATOR_REMOVE("/account/authenticator/remove"),
        EMAIL("/account/email"),
        DATA("/account#data"),
        DELETE("/account/delete");

        final String path;

        Next(final String path) {
            this.path = path;
        }

        String param() {
            return name().toLowerCase(Locale.ROOT).replace('_', '-');
        }

        static Next of(final String value) {
            for (final Next n : values()) {
                if (n.param().equals(value)) {
                    return n;
                }
            }
            return null;
        }
    }

    private final AccountOverviewService overview;
    private final AccountStepUp stepUp;

    public AccountConsoleSupport(final AccountOverviewService overview, final AccountStepUp stepUp) {
        this.overview = overview;
        this.stepUp = stepUp;
    }

    /** The signed-in user as a member of the request's realm; empty for anyone else (e.g. a session of another realm). */
    public Optional<UserAdminDto> member(final UserCredentials principal) {
        return principal == null ? Optional.empty() : overview.member(realm(), principal.getUserId());
    }

    /** Null when this session authenticated recently enough; otherwise the redirect to re-authenticate first. */
    String stepUp(final HttpServletRequest request, final Next next) {
        return stepUp.fresh(request) ? null : "redirect:/account/reauth?next=" + next.param();
    }

    /** Ends this browser's sign-in (the account was just locked); the caller returns {@link #LOCKED}. */
    static String endSession(final HttpServletRequest request) {
        final HttpSession session = request.getSession(false);
        if (session != null) {
            session.invalidate();
        }
        SecurityContextHolder.clearContext();
        return LOCKED;
    }

    static String realm() {
        return RealmContextHolder.get();
    }
}
