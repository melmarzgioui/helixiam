/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.controller.account.console;

import io.helixiam.authorization.amqp.user.UserAdminDto;
import io.helixiam.authorization.domain.UserCredentials;
import io.helixiam.authorization.service.account.AccountAudit;
import io.helixiam.authorization.service.account.AccountRateLimits;
import io.helixiam.authorization.service.account.EmailChangeService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.util.Map;
import java.util.Optional;

/**
 * B1: changing the email address ({@code /account/email}, step-up). The new address is stored unverified and a
 * confirmation link goes to it ({@link EmailChangeService}); the link itself is served by
 * {@link AccountEmailVerifyController}.
 */
@Controller
@AccountConsolePage
public class AccountEmailController {

    private final AccountConsoleSupport support;
    private final EmailChangeService emails;
    private final AccountRateLimits limits;
    private final AccountAudit audit;
    private final String idpBaseUrl;

    public AccountEmailController(final AccountConsoleSupport support, final EmailChangeService emails,
                                  final AccountRateLimits limits, final AccountAudit audit,
                                  @Value("${idp.base.url}") final String idpBaseUrl) {
        this.support = support;
        this.emails = emails;
        this.limits = limits;
        this.audit = audit;
        this.idpBaseUrl = idpBaseUrl;
    }

    @GetMapping("/account/email")
    public String form(@AuthenticationPrincipal final UserCredentials principal, final HttpServletRequest request,
                       final Model model) {
        final Optional<UserAdminDto> member = support.member(principal);
        if (member.isEmpty()) {
            return "redirect:/login";
        }
        final String stepUp = support.stepUp(request, AccountConsoleSupport.Next.EMAIL);
        if (stepUp != null) {
            return stepUp;
        }
        return page(model, member.get(), null, null);
    }

    @PostMapping("/account/email")
    public String change(@AuthenticationPrincipal final UserCredentials principal,
                         @RequestParam(required = false) final String email, final HttpServletRequest request,
                         final Model model, final RedirectAttributes flash) {
        final Optional<UserAdminDto> member = support.member(principal);
        if (member.isEmpty()) {
            return "redirect:/login";
        }
        final String stepUp = support.stepUp(request, AccountConsoleSupport.Next.EMAIL);
        if (stepUp != null) {
            return stepUp;
        }
        final UserAdminDto user = member.get();
        final String realm = AccountConsoleSupport.realm();
        if (!limits.allow(AccountRateLimits.Action.EMAIL, realm, user.userId())) {
            return page(model, user, email, "too-many");
        }
        final EmailChangeService.Outcome outcome = emails.change(realm, user.userId(), email,
                idpBaseUrl + "/realms/" + realm);
        switch (outcome) {
            case CHANGED -> {
                audit.emit(request, "ACCOUNT_EMAIL_CHANGE", realm, user.username(), user.userId(), AccountAudit.SUCCESS);
                flash.addFlashAttribute("status", "email-sent");
                return "redirect:/account";
            }
            case TAKEN -> {
                audit.emit(request, "ACCOUNT_EMAIL_CHANGE", realm, user.username(), user.userId(), AccountAudit.FAILURE,
                        Map.of("reason", "taken"));
                return page(model, user, email, "email-taken");
            }
            case SAME -> {
                return page(model, user, email, "email-same");
            }
            case UNKNOWN_USER -> {
                return "redirect:/login";
            }
            default -> {
                return page(model, user, email, "email-invalid");
            }
        }
    }

    private static String page(final Model model, final UserAdminDto user, final String typed, final String failure) {
        model.addAttribute("email", user.email());
        model.addAttribute("typed", typed);
        model.addAttribute("failure", failure);
        return "account/email";
    }
}
