/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.controller.account.console;

import io.helixiam.authorization.service.account.AccountAudit;
import io.helixiam.authorization.service.account.EmailChangeService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.util.Optional;

/**
 * B1: the link that confirms a changed email address ({@code GET /account/email/verify?token=…}). It works in any
 * browser, signed in or not (the single-use token is the proof of the mailbox), so it is not an account console page
 * and is open to anonymous requests; a wrong, used or expired link just says so.
 */
@Controller
public class AccountEmailVerifyController {

    private final EmailChangeService emails;
    private final AccountAudit audit;

    public AccountEmailVerifyController(final EmailChangeService emails, final AccountAudit audit) {
        this.emails = emails;
        this.audit = audit;
    }

    @GetMapping("/account/email/verify")
    public String verify(@RequestParam(required = false) final String token, final HttpServletRequest request,
                         final Model model) {
        final String realm = AccountConsoleSupport.realm();
        final Optional<EmailChangeService.Confirmed> confirmed = emails.confirm(realm, token);
        if (confirmed.isPresent()) {
            audit.emit(request, "ACCOUNT_EMAIL_VERIFY", realm, confirmed.get().email(), confirmed.get().userId(),
                    AccountAudit.SUCCESS);
        }
        model.addAttribute("notice", confirmed.isPresent() ? "emailVerified" : "emailInvalid");
        model.addAttribute("referrer", AccountConsoleAdvice.current(request));
        return "account/notice";
    }
}
