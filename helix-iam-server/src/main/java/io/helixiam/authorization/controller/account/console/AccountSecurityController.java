/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.controller.account.console;

import io.helixiam.authorization.amqp.mfa.MfaRecoveryPublisher;
import io.helixiam.authorization.amqp.user.CredentialRevokeRef;
import io.helixiam.authorization.amqp.user.UserAdminDto;
import io.helixiam.authorization.amqp.user.UserAdminPublisher;
import io.helixiam.authorization.amqp.user.UserChangePasswordDto;
import io.helixiam.authorization.domain.UserCredentials;
import io.helixiam.authorization.security.mfa.MfaSessionState;
import io.helixiam.authorization.security.mfa.totp.QrCode;
import io.helixiam.authorization.security.session.AuthTimeStamper;
import io.helixiam.authorization.service.account.AccountAudit;
import io.helixiam.authorization.service.account.AccountCredentialCheck;
import io.helixiam.authorization.service.account.AccountRateLimits;
import io.helixiam.authorization.service.mfa.MfaPolicyService;
import io.helixiam.authorization.service.mfa.TotpService;
import io.helixiam.authorization.service.security.PasswordPolicyEnforcer;
import io.helixiam.common.log.LogSafe;
import jakarta.servlet.http.HttpServletRequest;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * B1: the account console's security actions.
 * <ul>
 *   <li><b>Password</b> ({@code /account/password}): the current password is required (it is the re-authentication);
 *       the realm's password policy and history apply; a wrong current password counts toward the account lockout.</li>
 *   <li><b>Re-authentication</b> ({@code /account/reauth?next=…}): the step-up for sensitive actions — password, plus a
 *       code when an authenticator app is set up. Success stamps a new {@code auth_time}.</li>
 *   <li><b>Authenticator app</b> ({@code /account/authenticator}): set up, or move to a new app (step-up); the old
 *       secret stays valid until the new one is confirmed, and confirming issues new recovery codes.</li>
 *   <li><b>Remove it</b> ({@code /account/authenticator/remove}): step-up, only when the realm allows removal and does
 *       not require two-step verification; the recovery codes go with it.</li>
 *   <li><b>New recovery codes</b> ({@code POST /account/recovery-codes}): need a current code from the app.</li>
 * </ul>
 * Every change is audited ({@link AccountAudit}); attempts are rate limited per user ({@link AccountRateLimits}).
 */
@Controller
@AccountConsolePage
public class AccountSecurityController {

    private static final Logger LOG = LogManager.getLogger(AccountSecurityController.class);
    static final String PENDING_SECRET = "HELIX_ACCOUNT_PENDING_TOTP";

    private final AccountConsoleSupport support;
    private final UserAdminPublisher users;
    private final AccountCredentialCheck check;
    private final AccountRateLimits limits;
    private final AccountAudit audit;
    private final TotpService totp;
    private final MfaPolicyService mfaPolicy;
    private final MfaRecoveryPublisher recoveryCodes;
    private final QrCode qrCode;
    private final AccountOverviewService overview;

    public AccountSecurityController(final AccountConsoleSupport support, final UserAdminPublisher users,
                                     final AccountCredentialCheck check, final AccountRateLimits limits,
                                     final AccountAudit audit, final TotpService totp, final MfaPolicyService mfaPolicy,
                                     final MfaRecoveryPublisher recoveryCodes, final QrCode qrCode,
                                     final AccountOverviewService overview) {
        this.support = support;
        this.users = users;
        this.check = check;
        this.limits = limits;
        this.audit = audit;
        this.totp = totp;
        this.mfaPolicy = mfaPolicy;
        this.recoveryCodes = recoveryCodes;
        this.qrCode = qrCode;
        this.overview = overview;
    }

    // ------------------------------------------------------------------------------------------------ password

    @GetMapping("/account/password")
    public String passwordForm(@AuthenticationPrincipal final UserCredentials principal) {
        return support.member(principal).isPresent() ? "account/password" : "redirect:/login";
    }

    @PostMapping("/account/password")
    public String changePassword(@AuthenticationPrincipal final UserCredentials principal,
                                 @RequestParam(required = false) final String currentPassword,
                                 @RequestParam(required = false) final String newPassword,
                                 @RequestParam(required = false) final String confirmPassword,
                                 final HttpServletRequest request, final Model model, final RedirectAttributes flash) {
        final Optional<UserAdminDto> member = support.member(principal);
        if (member.isEmpty()) {
            return "redirect:/login";
        }
        final UserAdminDto user = member.get();
        final String realm = AccountConsoleSupport.realm();
        if (!limits.allow(AccountRateLimits.Action.PASSWORD, realm, user.userId())) {
            return passwordError(model, "too-many", null);
        }
        if (isBlank(currentPassword) || isBlank(newPassword)) {
            return passwordError(model, "password-required", null);
        }
        if (!newPassword.equals(confirmPassword)) {
            return passwordError(model, "password-mismatch", null);
        }
        final AccountCredentialCheck.Result current = check.password(realm, user.userId(), currentPassword);
        if (current == AccountCredentialCheck.Result.LOCKED) {
            audit.emit(request, "ACCOUNT_PASSWORD_CHANGE", realm, user.username(), user.userId(), AccountAudit.DENIED,
                    Map.of("reason", "locked"));
            return AccountConsoleSupport.endSession(request);
        }
        if (current == AccountCredentialCheck.Result.WRONG) {
            audit.emit(request, "ACCOUNT_PASSWORD_CHANGE", realm, user.username(), user.userId(), AccountAudit.FAILURE,
                    Map.of("reason", "wrong_current_password"));
            return passwordError(model, "password-wrong", null);
        }
        try {
            final boolean changed = Boolean.TRUE.equals(users.changePassword(
                    new UserChangePasswordDto(realm, user.userId(), currentPassword, newPassword)));
            if (!changed) {
                return passwordError(model, "password-wrong", null);
            }
        } catch (final PasswordPolicyEnforcer.PasswordPolicyException | IllegalArgumentException e) {
            audit.emit(request, "ACCOUNT_PASSWORD_CHANGE", realm, user.username(), user.userId(), AccountAudit.FAILURE,
                    Map.of("reason", "policy"));
            return passwordError(model, null, e.getMessage());
        }
        audit.emit(request, "ACCOUNT_PASSWORD_CHANGE", realm, user.username(), user.userId(), AccountAudit.SUCCESS);
        LOG.info("User {} changed their password in realm {}", LogSafe.sanitize(user.userId()), LogSafe.sanitize(realm));
        flash.addFlashAttribute("status", "password-changed");
        return "redirect:/account";
    }

    private static String passwordError(final Model model, final String key, final String policyMessage) {
        model.addAttribute("failure", key);
        model.addAttribute("policyMessage", policyMessage);
        return "account/password";
    }

    // ------------------------------------------------------------------------------------------ re-authentication

    @GetMapping("/account/reauth")
    public String reauthForm(@AuthenticationPrincipal final UserCredentials principal,
                             @RequestParam(required = false) final String next, final Model model) {
        final Optional<UserAdminDto> member = support.member(principal);
        if (member.isEmpty()) {
            return "redirect:/login";
        }
        return reauthPage(model, member.get(), next, null);
    }

    @PostMapping("/account/reauth")
    public String reauth(@AuthenticationPrincipal final UserCredentials principal,
                         @RequestParam(required = false) final String next,
                         @RequestParam(required = false) final String password,
                         @RequestParam(required = false) final String code,
                         final HttpServletRequest request, final Model model) {
        final Optional<UserAdminDto> member = support.member(principal);
        if (member.isEmpty()) {
            return "redirect:/login";
        }
        final UserAdminDto user = member.get();
        final String realm = AccountConsoleSupport.realm();
        if (!limits.allow(AccountRateLimits.Action.STEP_UP, realm, user.userId())) {
            return reauthPage(model, user, next, "too-many");
        }
        final boolean needsCode = totp.isEnrolled(user.userId());
        AccountCredentialCheck.Result result = check.password(realm, user.userId(), password);
        if (result == AccountCredentialCheck.Result.OK && needsCode) {
            result = check.totp(realm, user.userId(), code);
        }
        if (result == AccountCredentialCheck.Result.LOCKED) {
            audit.emit(request, "ACCOUNT_STEP_UP", realm, user.username(), user.userId(), AccountAudit.DENIED,
                    Map.of("reason", "locked"));
            return AccountConsoleSupport.endSession(request);
        }
        if (result != AccountCredentialCheck.Result.OK) {
            audit.emit(request, "ACCOUNT_STEP_UP", realm, user.username(), user.userId(), AccountAudit.FAILURE);
            return reauthPage(model, user, next, needsCode ? "password-wrong-or-code" : "password-wrong");
        }
        new AuthTimeStamper().stamp(request);
        if (needsCode) {
            MfaSessionState.markVerified(request, user.userId());
        }
        audit.emit(request, "ACCOUNT_STEP_UP", realm, user.username(), user.userId(), AccountAudit.SUCCESS,
                Map.of("method", needsCode ? "pwd+otp" : "pwd"));
        final AccountConsoleSupport.Next target = AccountConsoleSupport.Next.of(next);
        return "redirect:" + (target == null ? "/account" : target.path);
    }

    private String reauthPage(final Model model, final UserAdminDto user, final String next, final String failure) {
        final AccountConsoleSupport.Next target = AccountConsoleSupport.Next.of(next);
        model.addAttribute("next", target == null ? null : target.param());
        model.addAttribute("stepUpCode", totp.isEnrolled(user.userId()));
        model.addAttribute("username", user.username());
        model.addAttribute("failure", failure);
        return "account/reauth";
    }

    // ------------------------------------------------------------------------------------------- authenticator

    @GetMapping("/account/authenticator")
    public String authenticatorForm(@AuthenticationPrincipal final UserCredentials principal,
                                    final HttpServletRequest request, final Model model) {
        final Optional<UserAdminDto> member = support.member(principal);
        if (member.isEmpty()) {
            return "redirect:/login";
        }
        final String stepUp = support.stepUp(request, AccountConsoleSupport.Next.AUTHENTICATOR);
        if (stepUp != null) {
            return stepUp;
        }
        return authenticatorPage(member.get(), request, model, null);
    }

    @PostMapping("/account/authenticator")
    public String confirmAuthenticator(@AuthenticationPrincipal final UserCredentials principal,
                                       @RequestParam(required = false) final String code,
                                       final HttpServletRequest request, final Model model) {
        final Optional<UserAdminDto> member = support.member(principal);
        if (member.isEmpty()) {
            return "redirect:/login";
        }
        final String stepUp = support.stepUp(request, AccountConsoleSupport.Next.AUTHENTICATOR);
        if (stepUp != null) {
            return stepUp;
        }
        final UserAdminDto user = member.get();
        final String realm = AccountConsoleSupport.realm();
        final String secret = (String) request.getSession(true).getAttribute(PENDING_SECRET);
        if (!limits.allow(AccountRateLimits.Action.CODE, realm, user.userId())) {
            return authenticatorPage(user, request, model, "too-many");
        }
        final boolean replacing = totp.isEnrolled(user.userId());
        if (secret == null || !totp.confirmEnrolment(user.userId(), secret, code)) {
            audit.emit(request, "ACCOUNT_TOTP_ENROL", realm, user.username(), user.userId(), AccountAudit.FAILURE);
            return authenticatorPage(user, request, model, "code-invalid");
        }
        request.getSession().removeAttribute(PENDING_SECRET);
        // The user just proved the new factor: this sign-in counts as having passed the second step.
        MfaSessionState.markVerified(request, user.userId());
        final List<String> codes = recoveryCodes.generate(user.userId());
        audit.emit(request, "ACCOUNT_TOTP_ENROL", realm, user.username(), user.userId(), AccountAudit.SUCCESS,
                Map.of("replaced", String.valueOf(replacing)));
        model.addAttribute("recoveryCodes", codes);
        model.addAttribute("continueUrl", request.getContextPath() + "/account");
        return "mfa/recovery-codes";
    }

    private String authenticatorPage(final UserAdminDto user, final HttpServletRequest request, final Model model,
                                     final String failure) {
        String secret = (String) request.getSession(true).getAttribute(PENDING_SECRET);
        if (secret == null) {
            secret = totp.newSecret();
            request.getSession().setAttribute(PENDING_SECRET, secret);
        }
        final String account = user.email() == null || user.email().isBlank() ? user.username() : user.email();
        final String otpAuthUrl = TotpService.otpauthUri(mfaPolicy.issuer(AccountConsoleSupport.realm()), account, secret);
        model.addAttribute("qrCode", qrCode.dataUrl(otpAuthUrl));
        model.addAttribute("otpAuthUrl", otpAuthUrl);
        model.addAttribute("secret", secret);
        model.addAttribute("replacing", totp.isEnrolled(user.userId()));
        model.addAttribute("failure", failure);
        return "account/authenticator";
    }

    @GetMapping("/account/authenticator/remove")
    public String removeForm(@AuthenticationPrincipal final UserCredentials principal, final HttpServletRequest request,
                             final RedirectAttributes flash) {
        final Optional<UserAdminDto> member = support.member(principal);
        if (member.isEmpty()) {
            return "redirect:/login";
        }
        final String refused = removalRefused(member.get(), flash);
        if (refused != null) {
            return refused;
        }
        final String stepUp = support.stepUp(request, AccountConsoleSupport.Next.AUTHENTICATOR_REMOVE);
        return stepUp != null ? stepUp : "account/authenticator-remove";
    }

    @PostMapping("/account/authenticator/remove")
    public String remove(@AuthenticationPrincipal final UserCredentials principal, final HttpServletRequest request,
                         final RedirectAttributes flash) {
        final Optional<UserAdminDto> member = support.member(principal);
        if (member.isEmpty()) {
            return "redirect:/login";
        }
        final UserAdminDto user = member.get();
        final String realm = AccountConsoleSupport.realm();
        final String refused = removalRefused(user, flash);
        if (refused != null) {
            audit.emit(request, "ACCOUNT_TOTP_REMOVE", realm, user.username(), user.userId(), AccountAudit.DENIED);
            return refused;
        }
        final String stepUp = support.stepUp(request, AccountConsoleSupport.Next.AUTHENTICATOR_REMOVE);
        if (stepUp != null) {
            return stepUp;
        }
        users.revokeCredential(new CredentialRevokeRef(realm, user.userId(), "totp", "totp"));
        users.revokeCredential(new CredentialRevokeRef(realm, user.userId(), "recovery-code", "recovery-codes"));
        audit.emit(request, "ACCOUNT_TOTP_REMOVE", realm, user.username(), user.userId(), AccountAudit.SUCCESS);
        flash.addFlashAttribute("status", "authenticator-removed");
        return "redirect:/account";
    }

    /** Null when the user may remove their authenticator; otherwise where to send them. */
    private String removalRefused(final UserAdminDto user, final RedirectAttributes flash) {
        final AccountOverview.TwoStep state = overview.twoStep(AccountConsoleSupport.realm(), user.userId());
        if (!state.enrolled()) {
            flash.addFlashAttribute("failure", "not-enrolled");
            return "redirect:/account";
        }
        if (!state.canRemove()) {
            flash.addFlashAttribute("failure", "not-allowed");
            return "redirect:/account";
        }
        return null;
    }

    // ------------------------------------------------------------------------------------------ recovery codes

    @PostMapping("/account/recovery-codes")
    public String regenerateRecoveryCodes(@AuthenticationPrincipal final UserCredentials principal,
                                          @RequestParam(required = false) final String code,
                                          final HttpServletRequest request, final Model model,
                                          final RedirectAttributes flash) {
        final Optional<UserAdminDto> member = support.member(principal);
        if (member.isEmpty()) {
            return "redirect:/login";
        }
        final UserAdminDto user = member.get();
        final String realm = AccountConsoleSupport.realm();
        if (!totp.isEnrolled(user.userId())) {
            flash.addFlashAttribute("failure", "not-enrolled");
            return "redirect:/account";
        }
        if (!limits.allow(AccountRateLimits.Action.CODE, realm, user.userId())) {
            flash.addFlashAttribute("recoveryError", "too-many");
            return "redirect:/account#two-step";
        }
        final AccountCredentialCheck.Result result = check.totp(realm, user.userId(), code);
        if (result == AccountCredentialCheck.Result.LOCKED) {
            audit.emit(request, "ACCOUNT_RECOVERY_CODES_REGENERATE", realm, user.username(), user.userId(),
                    AccountAudit.DENIED, Map.of("reason", "locked"));
            return AccountConsoleSupport.endSession(request);
        }
        if (result != AccountCredentialCheck.Result.OK) {
            audit.emit(request, "ACCOUNT_RECOVERY_CODES_REGENERATE", realm, user.username(), user.userId(),
                    AccountAudit.FAILURE);
            flash.addFlashAttribute("recoveryError", "code-invalid");
            return "redirect:/account#two-step";
        }
        final List<String> codes = recoveryCodes.generate(user.userId());
        audit.emit(request, "ACCOUNT_RECOVERY_CODES_REGENERATE", realm, user.username(), user.userId(),
                AccountAudit.SUCCESS);
        model.addAttribute("recoveryCodes", codes);
        model.addAttribute("continueUrl", request.getContextPath() + "/account");
        return "mfa/recovery-codes";
    }

    private static boolean isBlank(final String v) {
        return v == null || v.isBlank();
    }
}
