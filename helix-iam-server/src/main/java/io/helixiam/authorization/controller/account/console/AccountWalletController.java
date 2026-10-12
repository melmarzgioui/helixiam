/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.controller.account.console;

import io.helixiam.authorization.amqp.user.UserAdminDto;
import io.helixiam.authorization.domain.UserCredentials;
import io.helixiam.authorization.federation.wallet.WalletIdentityProvider;
import io.helixiam.authorization.federation.wallet.WalletLinkFlow;
import io.helixiam.authorization.federation.wallet.WalletLinkService;
import io.helixiam.authorization.service.account.AccountAudit;
import io.helixiam.authorization.service.account.AccountRateLimits;
import io.helixiam.common.log.LogSafe;
import jakarta.servlet.http.HttpServletRequest;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.util.Locale;
import java.util.Map;
import java.util.Optional;

/**
 * Task 21b: "Link EU Digital Identity Wallet" in the account console (maintainer decision 1). The only way a wallet
 * without an administrative number reaches an account: the signed-in user binds it explicitly.
 * <ul>
 *   <li><b>Link</b> ({@code POST /account/wallet/link}, {@code alias}): a recent sign-in is required (the console's
 *       step-up, like the other sensitive actions), then a LINK wallet transaction of this user starts
 *       ({@link WalletLinkFlow#start}) and the browser goes to the wallet page.</li>
 *   <li><b>Callback</b> ({@code GET /account/wallet/{alias}/callback?response_code=}): where the wallet page (or a
 *       same-device wallet) returns. Linked only for the browser and the user that started it
 *       ({@link WalletLinkFlow#complete}); a wallet of another account is refused without saying which. Never a
 *       sign-in.</li>
 *   <li><b>Unlink</b> ({@code /account/wallet/unlink?alias=}, step-up): a confirmation page, then the POST removes the
 *       user's wallet links of that provider.</li>
 * </ul>
 * Every endpoint first checks that {@code alias} is a wallet provider of the request's realm (the registry is keyed by
 * alias only): otherwise 404. Every change is audited ({@code ACCOUNT_WALLET_LINK}, {@code ACCOUNT_WALLET_UNLINK});
 * link starts are rate limited per user. The outcome is shown in the console's wallet section
 * ({@code walletStatus} / {@code walletError}).
 */
@Controller
@AccountConsolePage
public class AccountWalletController {

    static final String BACK = "redirect:/account#wallets";
    private static final Logger LOG = LogManager.getLogger(AccountWalletController.class);

    private final AccountConsoleSupport support;
    private final AccountWallets wallets;
    private final WalletLinkFlow flow;
    private final WalletLinkService links;
    private final AccountRateLimits limits;
    private final AccountAudit audit;

    public AccountWalletController(final AccountConsoleSupport support, final AccountWallets wallets,
                                   final WalletLinkFlow flow, final WalletLinkService links,
                                   final AccountRateLimits limits, final AccountAudit audit) {
        this.support = support;
        this.wallets = wallets;
        this.flow = flow;
        this.links = links;
        this.limits = limits;
        this.audit = audit;
    }

    // ------------------------------------------------------------------------------------------------- link

    @PostMapping("/account/wallet/link")
    public String link(@AuthenticationPrincipal final UserCredentials principal,
                       @RequestParam(required = false) final String alias, final HttpServletRequest request,
                       final RedirectAttributes flash) {
        final Optional<UserAdminDto> member = support.member(principal);
        if (member.isEmpty()) {
            return "redirect:/login";
        }
        final String realm = AccountConsoleSupport.realm();
        final WalletIdentityProvider provider = provider(realm, alias);
        final String stepUp = support.stepUp(request, AccountConsoleSupport.Next.WALLETS);
        if (stepUp != null) {
            return stepUp;
        }
        final UserAdminDto user = member.get();
        if (!limits.allow(AccountRateLimits.Action.WALLET_LINK, realm, user.userId())) {
            return error(flash, alias, "too-many");
        }
        try {
            final String location = flow.start(provider, realm, user.userId(), request.getSession(true));
            // A full transaction store: say so here, in the console (the wallet page's "busy" page is a sign-in's).
            return location.endsWith("/wallet/unavailable") ? error(flash, alias, "busy") : "redirect:" + location;
        } catch (final IllegalStateException e) {
            LOG.warn("wallet: link could not start, realm={} alias={}: {}", LogSafe.sanitize(realm),
                    LogSafe.sanitize(alias), e.getClass().getSimpleName());
            return error(flash, alias, "refused");
        }
    }

    @GetMapping("/account/wallet/{alias}/callback")
    public String callback(@AuthenticationPrincipal final UserCredentials principal, @PathVariable final String alias,
                           @RequestParam(name = WalletIdentityProvider.RESPONSE_CODE_PARAM, required = false)
                           final String responseCode, final HttpServletRequest request,
                           final RedirectAttributes flash) {
        final Optional<UserAdminDto> member = support.member(principal);
        if (member.isEmpty()) {
            return "redirect:/login";
        }
        final String realm = AccountConsoleSupport.realm();
        final WalletIdentityProvider provider = provider(realm, alias);
        final UserAdminDto user = member.get();
        final WalletLinkFlow.Outcome outcome = flow.complete(provider, realm, user.userId(), responseCode,
                request.getSession(false));
        final boolean linked = outcome == WalletLinkFlow.Outcome.LINKED
                || outcome == WalletLinkFlow.Outcome.ALREADY_LINKED;
        audit.emit(request, "ACCOUNT_WALLET_LINK", realm, user.username(), user.userId(),
                linked ? AccountAudit.SUCCESS : AccountAudit.FAILURE,
                Map.of("idpAlias", alias, "result", outcome.name().toLowerCase(Locale.ROOT)));
        return switch (outcome) {
            case LINKED -> status(flash, alias, "linked");
            case ALREADY_LINKED -> status(flash, alias, "already-linked");
            case LINKED_TO_ANOTHER_USER -> error(flash, alias, "taken");
            case WEAK_SUBJECT_NOT_ACKNOWLEDGED -> error(flash, alias, "no-number");
            case MISSING_IDENTITY_ATTRIBUTES -> error(flash, alias, "missing-data");
            case STRATEGY_NOT_SUPPORTED -> error(flash, alias, "not-supported");
            case REFUSED -> error(flash, alias, "refused");
        };
    }

    // ------------------------------------------------------------------------------------------------ unlink

    @GetMapping("/account/wallet/unlink")
    public String unlinkForm(@AuthenticationPrincipal final UserCredentials principal,
                             @RequestParam(required = false) final String alias, final HttpServletRequest request,
                             final Model model, final RedirectAttributes flash) {
        final Optional<UserAdminDto> member = support.member(principal);
        if (member.isEmpty()) {
            return "redirect:/login";
        }
        final WalletIdentityProvider provider = provider(AccountConsoleSupport.realm(), alias);
        final String stepUp = support.stepUp(request, AccountConsoleSupport.Next.WALLETS);
        if (stepUp != null) {
            return stepUp;
        }
        if (!wallets.isLinked(member.get().userId(), alias)) {
            return error(flash, alias, "not-linked");
        }
        model.addAttribute("walletAlias", alias);
        model.addAttribute("walletName", provider.metadata().displayName());
        return "account/wallet-unlink";
    }

    @PostMapping("/account/wallet/unlink")
    public String unlink(@AuthenticationPrincipal final UserCredentials principal,
                         @RequestParam(required = false) final String alias, final HttpServletRequest request,
                         final RedirectAttributes flash) {
        final Optional<UserAdminDto> member = support.member(principal);
        if (member.isEmpty()) {
            return "redirect:/login";
        }
        final String realm = AccountConsoleSupport.realm();
        provider(realm, alias);
        final String stepUp = support.stepUp(request, AccountConsoleSupport.Next.WALLETS);
        if (stepUp != null) {
            return stepUp;
        }
        final UserAdminDto user = member.get();
        final int removed = links.unlink(realm, user.userId(), alias);
        audit.emit(request, "ACCOUNT_WALLET_UNLINK", realm, user.username(), user.userId(),
                removed > 0 ? AccountAudit.SUCCESS : AccountAudit.FAILURE,
                Map.of("idpAlias", alias, "removed", String.valueOf(removed)));
        return removed > 0 ? status(flash, alias, "unlinked") : error(flash, alias, "not-linked");
    }

    // ------------------------------------------------------------------------------------------------ helpers

    /** Ruling 3: the alias must name a wallet provider of this realm; anything else is a 404. */
    private WalletIdentityProvider provider(final String realm, final String alias) {
        return wallets.provider(realm, alias).orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND));
    }

    private static String status(final RedirectAttributes flash, final String alias, final String key) {
        flash.addFlashAttribute("walletStatus", key);
        flash.addFlashAttribute("walletAlias", alias);
        return BACK;
    }

    private static String error(final RedirectAttributes flash, final String alias, final String key) {
        flash.addFlashAttribute("walletError", key);
        flash.addFlashAttribute("walletAlias", alias);
        return BACK;
    }
}
