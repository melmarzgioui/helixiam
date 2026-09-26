/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.controller.account;

import io.helixiam.authorization.amqp.mfa.MfaRecoveryPublisher;
import io.helixiam.authorization.domain.UserCredentials;
import io.helixiam.authorization.service.mfa.TotpService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

/**
 * 1.0 item 6: the signed-in user regenerates their TOTP recovery codes. The previous set stops working; the new
 * codes are returned once (only their hashes are stored). 409 when the user has not enrolled TOTP.
 */
@RestController
@RequestMapping("/account/mfa")
public class AccountMfaController {

    private final TotpService totp;
    private final MfaRecoveryPublisher recoveryCodes;

    public AccountMfaController(final TotpService totp, final MfaRecoveryPublisher recoveryCodes) {
        this.totp = totp;
        this.recoveryCodes = recoveryCodes;
    }

    @PostMapping("/recovery-codes")
    public ResponseEntity<Map<String, List<String>>> regenerate(@AuthenticationPrincipal final UserCredentials principal) {
        if (principal == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
        if (!totp.isEnrolled(principal.getUserId())) {
            return ResponseEntity.status(HttpStatus.CONFLICT).build();
        }
        return ResponseEntity.ok(Map.of("recoveryCodes", recoveryCodes.generate(principal.getUserId())));
    }
}
