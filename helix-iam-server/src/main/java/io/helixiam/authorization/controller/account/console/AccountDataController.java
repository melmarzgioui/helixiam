/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.controller.account.console;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.helixiam.authorization.amqp.gdpr.GdprExportDto;
import io.helixiam.authorization.amqp.gdpr.GdprPublisher;
import io.helixiam.authorization.amqp.gdpr.GdprUserRef;
import io.helixiam.authorization.amqp.user.UserAdminDto;
import io.helixiam.authorization.amqp.user.UserAdminPublisher;
import io.helixiam.authorization.amqp.user.UserAdminRef;
import io.helixiam.authorization.domain.UserCredentials;
import io.helixiam.authorization.service.account.AccountAudit;
import io.helixiam.authorization.service.account.AccountConsoleSettingsService;
import io.helixiam.authorization.service.account.AccountRateLimits;
import io.helixiam.authorization.service.account.AccountReferrer;
import io.helixiam.authorization.session.AccountSessionService;
import io.helixiam.authorization.session.SessionRevocation;
import io.helixiam.common.log.LogSafe;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.http.ContentDisposition;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.FlashMap;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;
import org.springframework.web.servlet.support.RequestContextUtils;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.Optional;

/**
 * B1: the user's data, where the realm allows it (account console settings).
 * <ul>
 *   <li><b>Download</b> ({@code POST /account/export}, step-up): the same secret-free GDPR Art. 15/20 export the
 *       account API serves, as a JSON file.</li>
 *   <li><b>Delete the account</b> ({@code /account/delete}, step-up, the user types their username): every sign-in of the
 *       user ends — their applications get a back-channel logout, other browsers are signed out
 *       ({@link SessionRevocation}) — then the user is removed from the realm (and deleted when it was their only
 *       realm), this browser's session ends, and a page confirms it with the return link.</li>
 * </ul>
 */
@Controller
@AccountConsolePage
public class AccountDataController {

    private static final Logger LOG = LogManager.getLogger(AccountDataController.class);

    private final AccountConsoleSupport support;
    private final AccountConsoleSettingsService settings;
    private final GdprPublisher gdpr;
    private final UserAdminPublisher users;
    private final AccountSessionService sessions;
    private final SessionRevocation revocation;
    private final AccountRateLimits limits;
    private final AccountAudit audit;
    private final ObjectMapper json;

    public AccountDataController(final AccountConsoleSupport support, final AccountConsoleSettingsService settings,
                                 final GdprPublisher gdpr, final UserAdminPublisher users,
                                 final AccountSessionService sessions, final SessionRevocation revocation,
                                 final AccountRateLimits limits, final AccountAudit audit, final ObjectMapper json) {
        this.support = support;
        this.settings = settings;
        this.gdpr = gdpr;
        this.users = users;
        this.sessions = sessions;
        this.revocation = revocation;
        this.limits = limits;
        this.audit = audit;
        this.json = json;
    }

    // ------------------------------------------------------------------------------------------------- export

    @PostMapping("/account/export")
    public ResponseEntity<byte[]> export(@AuthenticationPrincipal final UserCredentials principal,
                                         final HttpServletRequest request, final HttpServletResponse response)
            throws java.io.IOException {
        final Optional<UserAdminDto> member = support.member(principal);
        if (member.isEmpty()) {
            return redirect(request, "/login");
        }
        final UserAdminDto user = member.get();
        final String realm = AccountConsoleSupport.realm();
        if (!settings.get(realm).dataExport()) {
            audit.emit(request, "ACCOUNT_DATA_EXPORT", realm, user.username(), user.userId(), AccountAudit.DENIED);
            return redirectWithFailure(request, response, "not-allowed");
        }
        final String stepUp = support.stepUp(request, AccountConsoleSupport.Next.DATA);
        if (stepUp != null) {
            return redirect(request, stepUp.substring("redirect:".length()));
        }
        if (!limits.allow(AccountRateLimits.Action.EXPORT, realm, user.userId())) {
            return redirectWithFailure(request, response, "too-many");
        }
        final GdprExportDto export = gdpr.export(new GdprUserRef(realm, user.userId()));
        if (export == null) {
            return redirect(request, "/login");
        }
        audit.emit(request, "ACCOUNT_DATA_EXPORT", realm, user.username(), user.userId(), AccountAudit.SUCCESS);
        final String filename = "account-data-" + realm.replaceAll("[^A-Za-z0-9._-]", "_") + ".json";
        return ResponseEntity.ok()
                .contentType(MediaType.APPLICATION_JSON)
                .header(HttpHeaders.CONTENT_DISPOSITION, ContentDisposition.attachment()
                        .filename(filename, StandardCharsets.UTF_8).build().toString())
                .header(HttpHeaders.CACHE_CONTROL, "no-store")
                .body(json.writerWithDefaultPrettyPrinter().writeValueAsBytes(export));
    }

    private static ResponseEntity<byte[]> redirect(final HttpServletRequest request, final String path) {
        return ResponseEntity.status(HttpStatus.FOUND).location(URI.create(request.getContextPath() + path)).build();
    }

    private static ResponseEntity<byte[]> redirectWithFailure(final HttpServletRequest request,
                                                              final HttpServletResponse response, final String failure) {
        final FlashMap flash = RequestContextUtils.getOutputFlashMap(request);
        flash.put("failure", failure);
        RequestContextUtils.saveOutputFlashMap(request.getContextPath() + "/account", request, response);
        return redirect(request, "/account");
    }

    // ------------------------------------------------------------------------------------------------- delete

    @GetMapping("/account/delete")
    public String deleteForm(@AuthenticationPrincipal final UserCredentials principal, final HttpServletRequest request,
                             final Model model, final RedirectAttributes flash) {
        final Optional<UserAdminDto> member = support.member(principal);
        if (member.isEmpty()) {
            return "redirect:/login";
        }
        if (!settings.get(AccountConsoleSupport.realm()).accountDeletion()) {
            flash.addFlashAttribute("failure", "not-allowed");
            return "redirect:/account";
        }
        final String stepUp = support.stepUp(request, AccountConsoleSupport.Next.DELETE);
        if (stepUp != null) {
            return stepUp;
        }
        model.addAttribute("username", member.get().username());
        return "account/delete";
    }

    @PostMapping("/account/delete")
    public String delete(@AuthenticationPrincipal final UserCredentials principal,
                         @RequestParam(required = false) final String confirm, final HttpServletRequest request,
                         final Model model, final RedirectAttributes flash) {
        final Optional<UserAdminDto> member = support.member(principal);
        if (member.isEmpty()) {
            return "redirect:/login";
        }
        final UserAdminDto user = member.get();
        final String realm = AccountConsoleSupport.realm();
        if (!settings.get(realm).accountDeletion()) {
            audit.emit(request, "ACCOUNT_DELETE", realm, user.username(), user.userId(), AccountAudit.DENIED);
            flash.addFlashAttribute("failure", "not-allowed");
            return "redirect:/account";
        }
        final String stepUp = support.stepUp(request, AccountConsoleSupport.Next.DELETE);
        if (stepUp != null) {
            return stepUp;
        }
        if (confirm == null || !confirm.trim().equals(user.username())) {
            model.addAttribute("username", user.username());
            model.addAttribute("failure", "confirm-mismatch");
            return "account/delete";
        }
        final AccountReferrer.Link referrer = AccountConsoleAdvice.current(request);
        final int ended = sessions.signOutAll(realm, user.userId());
        revocation.revokeAll(user.userId());
        final boolean removed = Boolean.TRUE.equals(users.delete(new UserAdminRef(realm, user.userId())));
        audit.emit(request, "ACCOUNT_DELETE", realm, user.username(), user.userId(),
                removed ? AccountAudit.SUCCESS : AccountAudit.FAILURE, Map.of("ssoSessionsEnded", String.valueOf(ended)));
        LOG.info("User {} deleted their account in realm {}", LogSafe.sanitize(user.userId()), LogSafe.sanitize(realm));
        final HttpSession session = request.getSession(false);
        if (session != null) {
            session.invalidate();
        }
        SecurityContextHolder.clearContext();
        model.addAttribute("notice", "deleted");
        model.addAttribute("referrer", referrer);
        return "account/notice";
    }
}
