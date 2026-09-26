/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.security.mfa.controller;

import io.helixiam.authorization.amqp.mfa.MfaRecoveryPublisher;
import io.helixiam.authorization.amqp.mfa.RecoveryCodeVerification;
import io.helixiam.authorization.domain.UserCredentials;
import io.helixiam.authorization.security.flow.ResolveSavedRequestRedirect;
import io.helixiam.authorization.security.mfa.MfaSessionState;
import io.helixiam.authorization.security.mfa.totp.QrCode;
import io.helixiam.authorization.security.realm.RealmContextHolder;
import io.helixiam.authorization.service.MfaService;
import io.helixiam.authorization.service.mfa.MfaPolicyService;
import io.helixiam.authorization.service.mfa.TotpService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.util.List;

/**
 * The second step of sign-in: TOTP enrolment ({@code /mfa/enable}), TOTP ({@code /mfa/totp}) and recovery codes
 * ({@code /mfa/recovery}). All paths are realm-relative (served under {@code /realms/{realm}}).
 *
 * <p>1.0 item 6: enrolment generates a fresh secret held in the session until the user confirms it with a valid
 * code; only then is it stored and TOTP switched on, and a set of single-use recovery codes is shown once.
 * Skipping enrolment is possible only within the realm's grace period (off by default). Passing any of these
 * marks the session ({@link MfaSessionState}) so {@code /oauth2/authorize} can issue a code.
 */
@Controller
public class MfaAuthController {
    private static final String REDIRECT_PREFIX = "redirect:";
    static final String PENDING_SECRET = "HELIX_MFA_PENDING_SECRET";
    private final QrCode qrCode;
    private final MfaService mfaService;
    private final TotpService totp;
    private final MfaPolicyService policy;
    private final MfaRecoveryPublisher recoveryCodes;
    private final String spBaseUrl;
    private final io.helixiam.authorization.security.realm.SessionPolicyApplier sessionPolicyApplier;
    // SSO P1: after the second factor promotes the session, resume the originating /oauth2/authorize.
    private final ResolveSavedRequestRedirect savedRequestRedirect = new ResolveSavedRequestRedirect();
    private final io.helixiam.authorization.security.session.AuthTimeStamper authTimeStamper =
            new io.helixiam.authorization.security.session.AuthTimeStamper();

    @Autowired
    public MfaAuthController(final QrCode qrCode, final MfaService mfaService, final TotpService totp,
                             final MfaPolicyService policy, final MfaRecoveryPublisher recoveryCodes,
                             @Value("${sp.base.url}") final String spBaseUrl,
                             final io.helixiam.authorization.security.realm.SessionPolicyApplier sessionPolicyApplier) {
        this.qrCode = qrCode;
        this.mfaService = mfaService;
        this.totp = totp;
        this.policy = policy;
        this.recoveryCodes = recoveryCodes;
        this.spBaseUrl = spBaseUrl;
        this.sessionPolicyApplier = sessionPolicyApplier;
    }

    @GetMapping(path = "/mfa/enable")
    public String requestEnableMfaFactor(@AuthenticationPrincipal final UserCredentials user, final Model model,
                                         final HttpServletRequest request) {
        if (totp.isEnrolled(user.getUsername())) {
            return REDIRECT_PREFIX + "/mfa/totp";
        }
        final HttpSession session = request.getSession(true);
        String secret = (String) session.getAttribute(PENDING_SECRET);
        if (secret == null) {
            secret = totp.newSecret();
            session.setAttribute(PENDING_SECRET, secret);
        }
        final String realm = RealmContextHolder.get();
        final String otpAuthUrl = TotpService.otpauthUri(policy.issuer(realm), user.getEmail(), secret);
        model.addAttribute("qrCode", this.qrCode.dataUrl(otpAuthUrl));
        model.addAttribute("otpAuthUrl", otpAuthUrl);
        model.addAttribute("secret", secret);
        model.addAttribute("skipEnable", policy.maySkip(realm, user.getCreationDate()));
        return "mfa/enable";
    }

    @PostMapping(path = "/mfa/enable")
    public String processEnableMfaFactor(@RequestParam final String code, @AuthenticationPrincipal final UserCredentials user,
                                         final Model model, final HttpServletRequest request, final HttpServletResponse response) {
        final String realm = RealmContextHolder.get();
        if ("skip".equals(code)) {
            if (policy.maySkip(realm, user.getCreationDate())) {
                return complete(user, request, response);
            }
            model.addAttribute("error", "true");
            return requestEnableMfaFactor(user, model, request);
        }
        if (totp.isEnrolled(user.getUsername())) {
            return REDIRECT_PREFIX + "/mfa/totp";
        }
        final String secret = (String) request.getSession(true).getAttribute(PENDING_SECRET);
        if (secret == null || !totp.confirmEnrolment(user.getUsername(), secret, code)) {
            model.addAttribute("error", "true");
            return requestEnableMfaFactor(user, model, request);
        }
        request.getSession().removeAttribute(PENDING_SECRET);
        final List<String> codes = recoveryCodes.generate(user.getUsername());
        final String next = complete(user, request, response).substring(REDIRECT_PREFIX.length());
        model.addAttribute("recoveryCodes", codes);
        model.addAttribute("continueUrl", next);
        return "mfa/recovery-codes";
    }

    @GetMapping(path = "/mfa/totp")
    public String requestTotp() {
        return "mfa/totp";
    }

    @PostMapping(path = "/mfa/totp")
    public String processTotp(@RequestParam final String code, @AuthenticationPrincipal final UserCredentials user, final Model model,
                              final HttpServletRequest request, final HttpServletResponse response) {
        if (!totp.verify(user.getUsername(), code)) {
            model.addAttribute("error", "true");
            return requestTotp();
        }
        return complete(user, request, response);
    }

    @PostMapping(path = "/mfa/recovery")
    public String processRecoveryCode(@RequestParam final String recoveryCode, @AuthenticationPrincipal final UserCredentials user,
                                      final Model model, final HttpServletRequest request, final HttpServletResponse response) {
        if (!Boolean.TRUE.equals(recoveryCodes.verifyAndConsume(new RecoveryCodeVerification(user.getUsername(), recoveryCode)))) {
            model.addAttribute("recoveryError", "true");
            return requestTotp();
        }
        return complete(user, request, response);
    }

    /** Second factor passed: restore the full authentication, mark the session, resume the authorize request. */
    private String complete(final UserCredentials user, final HttpServletRequest request, final HttpServletResponse response) {
        mfaService.unlockUser();
        MfaSessionState.markVerified(request, user.getUsername());
        authTimeStamper.stamp(request); // SSO P2
        sessionPolicyApplier.applyOnLogin(request, RealmContextHolder.get()); // SSO P3
        return savedRequestRedirect.redirectView(request, response, spBaseUrl);
    }
}
