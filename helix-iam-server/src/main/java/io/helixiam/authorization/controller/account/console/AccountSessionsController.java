/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.controller.account.console;

import io.helixiam.authorization.amqp.user.UserAdminDto;
import io.helixiam.authorization.domain.UserCredentials;
import io.helixiam.authorization.security.session.AuthTimeStamper;
import io.helixiam.authorization.service.account.AccountAudit;
import io.helixiam.authorization.session.AccountSessionService;
import io.helixiam.authorization.session.SessionRevocation;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.util.Map;
import java.util.Optional;

/**
 * B1: "sign out everywhere else". Every other sign-in of the user in this realm ends: its applications' tokens are
 * revoked and they get a back-channel logout ({@link AccountSessionService#signOutOthers}), and every other browser
 * session — in whichever store — is ended on its next request ({@link SessionRevocation}). This browser stays signed
 * in. Only the user's own sessions are ever touched.
 */
@Controller
@AccountConsolePage
public class AccountSessionsController {

    private final AccountConsoleSupport support;
    private final AccountSessionService sessions;
    private final SessionRevocation revocation;
    private final AccountAudit audit;

    public AccountSessionsController(final AccountConsoleSupport support, final AccountSessionService sessions,
                                     final SessionRevocation revocation, final AccountAudit audit) {
        this.support = support;
        this.sessions = sessions;
        this.revocation = revocation;
        this.audit = audit;
    }

    @PostMapping("/account/sessions/sign-out-others")
    public String signOutOthers(@AuthenticationPrincipal final UserCredentials principal, final HttpServletRequest request,
                                final RedirectAttributes flash) {
        final Optional<UserAdminDto> member = support.member(principal);
        if (member.isEmpty()) {
            return "redirect:/login";
        }
        final UserAdminDto user = member.get();
        final String realm = AccountConsoleSupport.realm();
        final int ended = sessions.signOutOthers(realm, user.userId(), AuthTimeStamper.readSid(request));
        final long revokedAt = revocation.revokeAll(user.userId());
        request.getSession(true).setAttribute(SessionRevocation.KEPT_ATTRIBUTE, revokedAt);
        audit.emit(request, "ACCOUNT_SESSIONS_SIGN_OUT_OTHERS", realm, user.username(), user.userId(),
                AccountAudit.SUCCESS, Map.of("ssoSessionsEnded", String.valueOf(ended)));
        flash.addFlashAttribute("status", "signed-out-others");
        return "redirect:/account#sessions";
    }
}
