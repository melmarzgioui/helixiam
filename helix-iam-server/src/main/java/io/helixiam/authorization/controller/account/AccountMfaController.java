/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.controller.account;

import io.helixiam.authorization.amqp.mfa.MfaRecoveryPublisher;
import io.helixiam.authorization.domain.UserCredentials;
import io.helixiam.authorization.security.realm.RealmContextHolder;
import io.helixiam.authorization.service.account.AccountCredentialCheck;
import io.helixiam.authorization.service.account.AccountStepUp;
import jakarta.servlet.http.HttpServletRequest;
import io.helixiam.authorization.service.mfa.TotpService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

/**
 * 1.0 item 6: the signed-in user regenerates their TOTP recovery codes. The previous set stops working; the new
 * codes are returned once (only their hashes are stored). 409 when the user has not enrolled TOTP.
 *
 * <p>B1: it needs a fresh proof of the second factor — a current authenticator code in the body
 * ({@code {"code":"123456"}}), or a sign-in within the account console's step-up window ({@link AccountStepUp});
 * otherwise 403 {@code {"error":"step_up_required"}}. A wrong code is 400 and counts toward the account lockout.
 */
@RestController
@RequestMapping("/account/mfa")
public class AccountMfaController {

    private final TotpService totp;
    private final MfaRecoveryPublisher recoveryCodes;
    private final AccountStepUp stepUp;
    private final AccountCredentialCheck check;

    public AccountMfaController(final TotpService totp, final MfaRecoveryPublisher recoveryCodes,
                                final AccountStepUp stepUp, final AccountCredentialCheck check) {
        this.totp = totp;
        this.recoveryCodes = recoveryCodes;
        this.stepUp = stepUp;
        this.check = check;
    }

    /** Optional body: a current authenticator code. */
    public record RegenerateRequest(String code) {
    }

    @PostMapping("/recovery-codes")
    public ResponseEntity<Map<String, ?>> regenerate(@AuthenticationPrincipal final UserCredentials principal,
                                                     @RequestBody(required = false) final RegenerateRequest body,
                                                     final HttpServletRequest request) {
        if (principal == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
        if (!totp.isEnrolled(principal.getUserId())) {
            return ResponseEntity.status(HttpStatus.CONFLICT).build();
        }
        final String code = body == null ? null : body.code();
        if (code != null && !code.isBlank()) {
            if (check.totp(RealmContextHolder.get(), principal.getUserId(), code) != AccountCredentialCheck.Result.OK) {
                return ResponseEntity.badRequest().body(Map.of("error", "invalid_code"));
            }
        } else if (!stepUp.fresh(request)) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body(Map.of("error", "step_up_required"));
        }
        return ResponseEntity.ok(Map.of("recoveryCodes", recoveryCodes.generate(principal.getUserId())));
    }
}
