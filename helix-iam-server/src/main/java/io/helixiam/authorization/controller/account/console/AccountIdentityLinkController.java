/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.controller.account.console;

import io.helixiam.authorization.amqp.user.UserAdminDto;
import io.helixiam.authorization.domain.UserCredentials;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.util.Optional;

/**
 * Round 6: "Link" an identity provider in the account console's Connected accounts. A recent sign-in is required
 * (the console's {@code max_age} step-up); then {@link AccountIdentityLinkFlow} binds the request to this session and
 * the browser goes to the provider through the broker in link mode. The broker returns to {@code /account#identities}
 * with the outcome. The form is CSRF-protected like every console form.
 */
@Controller
@AccountConsolePage
public class AccountIdentityLinkController {

    static final String BACK = "redirect:/account#identities";

    private final AccountConsoleSupport support;
    private final AccountIdentityLinkFlow flow;

    public AccountIdentityLinkController(final AccountConsoleSupport support, final AccountIdentityLinkFlow flow) {
        this.support = support;
        this.flow = flow;
    }

    @PostMapping("/account/identities/link")
    public String link(@AuthenticationPrincipal final UserCredentials principal,
                       @RequestParam(required = false) final String alias, final HttpServletRequest request,
                       final RedirectAttributes flash) {
        final Optional<UserAdminDto> member = support.member(principal);
        if (member.isEmpty()) {
            return "redirect:/login";
        }
        if (alias == null || alias.isBlank()) {
            flash.addFlashAttribute("identityError", "choose");
            return BACK;
        }
        if (!flow.linkable(AccountConsoleSupport.realm(), alias)) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND);
        }
        flow.remember(request.getSession(true), alias);
        final String stepUp = support.stepUp(request, AccountConsoleSupport.Next.IDENTITY_LINK);
        return stepUp != null ? stepUp : start(member.get(), request);
    }

    /** Where the step-up returns: continues the link this session asked for (nothing else can be started here). */
    @GetMapping("/account/identities/link/continue")
    public String resume(@AuthenticationPrincipal final UserCredentials principal, final HttpServletRequest request) {
        final Optional<UserAdminDto> member = support.member(principal);
        if (member.isEmpty()) {
            return "redirect:/login";
        }
        final String stepUp = support.stepUp(request, AccountConsoleSupport.Next.IDENTITY_LINK);
        return stepUp != null ? stepUp : start(member.get(), request);
    }

    private String start(final UserAdminDto user, final HttpServletRequest request) {
        final HttpSession session = request.getSession(true);
        final String realm = AccountConsoleSupport.realm();
        final String alias = flow.takePending(session).filter(a -> flow.linkable(realm, a)).orElse(null);
        return alias == null ? BACK : "redirect:" + flow.brokerPath(session, realm, user.userId(), alias);
    }
}
