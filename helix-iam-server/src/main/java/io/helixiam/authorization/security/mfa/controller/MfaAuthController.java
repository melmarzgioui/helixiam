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
    static final String FAILURES = "HELIX_MFA_FAILURES";
    /** Wrong second-factor codes allowed in one sign-in; the next one ends it (the password is needed again). */
    static final int MAX_FAILURES_PER_SIGN_IN = 5;
    private static final String LOCKED_REDIRECT = "redirect:/login?error=mfaLocked";
    private final QrCode qrCode;
    private final MfaService mfaService;
    private final TotpService totp;
    private final MfaPolicyService policy;
    private final MfaRecoveryPublisher recoveryCodes;
    private final String spBaseUrl;
    private final io.helixiam.authorization.security.realm.SessionPolicyApplier sessionPolicyApplier;
    @Autowired(required = false)
    private io.helixiam.authorization.controller.BrandingSupport brandingSupport;
    @Autowired(required = false)
    private io.helixiam.authorization.service.security.LoginFailureService loginFailures;
    @Autowired(required = false)
    private io.helixiam.authorization.repository.realm.RealmConfigRepository realmConfigs;
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
        brand(model);
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
            if (failed(user, request)) {
                return LOCKED_REDIRECT;
            }
            model.addAttribute("error", "true");
            return requestEnableMfaFactor(user, model, request);
        }
        request.getSession().removeAttribute(PENDING_SECRET);
        final List<String> codes = recoveryCodes.generate(user.getUsername());
        final String next = complete(user, request, response).substring(REDIRECT_PREFIX.length());
        model.addAttribute("recoveryCodes", codes);
        model.addAttribute("continueUrl", next);
        brand(model);
        return "mfa/recovery-codes";
    }

    @GetMapping(path = "/mfa/totp")
    public String requestTotp(final Model model) {
        brand(model);
        return "mfa/totp";
    }

    /** Realm branding, overridden by the organization in context (1.0 item 7). */
    private void brand(final Model model) {
        if (brandingSupport != null) {
            brandingSupport.apply(model);
        }
    }

    @PostMapping(path = "/mfa/totp")
    public String processTotp(@RequestParam final String code, @AuthenticationPrincipal final UserCredentials user, final Model model,
                              final HttpServletRequest request, final HttpServletResponse response) {
        if (lockedOut(user)) {
            return endSignIn(request);
        }
        if (!totp.verify(user.getUsername(), code)) {
            if (failed(user, request)) {
                return LOCKED_REDIRECT;
            }
            model.addAttribute("error", "true");
            return requestTotp(model);
        }
        return complete(user, request, response);
    }

    @PostMapping(path = "/mfa/recovery")
    public String processRecoveryCode(@RequestParam final String recoveryCode, @AuthenticationPrincipal final UserCredentials user,
                                      final Model model, final HttpServletRequest request, final HttpServletResponse response) {
        if (lockedOut(user)) {
            return endSignIn(request);
        }
        if (!Boolean.TRUE.equals(recoveryCodes.verifyAndConsume(new RecoveryCodeVerification(user.getUsername(), recoveryCode)))) {
            if (failed(user, request)) {
                return LOCKED_REDIRECT;
            }
            model.addAttribute("recoveryError", "true");
            return requestTotp(model);
        }
        return complete(user, request, response);
    }

    /**
     * A wrong second-factor code. It counts toward the realm's account lockout (like a wrong password) and toward
     * this sign-in's cap; at the cap — or when the account is now locked — the sign-in ends. True = ended.
     */
    private boolean failed(final UserCredentials user, final HttpServletRequest request) {
        final jakarta.servlet.http.HttpSession session = request.getSession(true);
        final Integer previous = (Integer) session.getAttribute(FAILURES);
        final int failures = (previous == null ? 0 : previous) + 1;
        session.setAttribute(FAILURES, failures);
        boolean locked = false;
        if (loginFailures != null && realmConfigs != null) {
            final var realm = realmConfigs.findById(RealmContextHolder.get()).orElse(null);
            locked = realm != null && loginFailures.recordFailure(realm, user.getUsername());
        }
        if (failures >= MAX_FAILURES_PER_SIGN_IN || locked) {
            endSignIn(request);
            return true;
        }
        return false;
    }

    private boolean lockedOut(final UserCredentials user) {
        if (loginFailures == null || realmConfigs == null) {
            return false;
        }
        return realmConfigs.findById(RealmContextHolder.get())
                .map(realm -> loginFailures.isLockedOut(realm, user.getUsername())).orElse(false);
    }

    /** Throws away this sign-in (session and authentication): the user starts again with their password. */
    private String endSignIn(final HttpServletRequest request) {
        final jakarta.servlet.http.HttpSession session = request.getSession(false);
        if (session != null) {
            session.invalidate();
        }
        org.springframework.security.core.context.SecurityContextHolder.clearContext();
        return LOCKED_REDIRECT;
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
