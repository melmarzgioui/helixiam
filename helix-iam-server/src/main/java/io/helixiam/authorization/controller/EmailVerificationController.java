/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.controller;

import io.helixiam.authorization.security.audit.AuditContext;
import io.helixiam.authorization.security.audit.AuditEvent;
import io.helixiam.authorization.security.audit.AuditLog;
import io.helixiam.authorization.security.realm.RealmContextHolder;
import io.helixiam.authorization.service.emailverification.EmailVerificationService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.util.Optional;

/**
 * C3: the emailed verification link ({@code /realms/{r}/verify-email?token=…}), realm-relative.
 * <ol>
 *   <li>{@code GET}: a confirmation page only — mail scanners that prefetch links do not use the link up.</li>
 *   <li>{@code POST}: consumes the link once, marks the address verified and clears the {@code VERIFY_EMAIL}
 *       required action. It does not sign anyone in: the user continues in the sign-in window.</li>
 * </ol>
 */
@Controller
public class EmailVerificationController {

    private final EmailVerificationService verification;
    private final BrandingSupport branding;
    private final AuditLog auditLog;

    public EmailVerificationController(final EmailVerificationService verification, final BrandingSupport branding,
                                       final AuditLog auditLog) {
        this.verification = verification;
        this.branding = branding;
        this.auditLog = auditLog;
    }

    @GetMapping("/verify-email")
    public String confirmPage(@RequestParam(required = false) final String token, final Model model) {
        model.addAttribute("token", token);
        branding.apply(model);
        return "verify/confirm";
    }

    @PostMapping("/verify-email")
    public String verify(@RequestParam(required = false) final String token, final HttpServletRequest request,
                         final HttpServletResponse response, final Model model) {
        final String realm = RealmContextHolder.get();
        final Optional<String> userId = verification.consume(realm, token);
        if (userId.isEmpty()) {
            response.setStatus(HttpStatus.BAD_REQUEST.value());
        } else {
            auditLog.emit(AuditEvent.authn(AuditContext.nowIso(), "EMAIL_VERIFIED", realm, userId.get(),
                    AuditContext.clientIp(request), "SUCCESS", null));
        }
        model.addAttribute("verified", userId.isPresent());
        branding.apply(model);
        return "verify/done";
    }
}
