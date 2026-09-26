/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.controller.admin;

import io.helixiam.authorization.service.mfa.MfaPolicyService;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * 1.0 item 6: the realm's two-step sign-in policy — whether TOTP is required and how many days a new account may
 * skip enrolment (0 = never, the default). PUT updates only the fields present.
 */
@RestController
@RequestMapping("/admin/realms/{realmId}/settings/mfa")
public class MfaPolicyController {

    private final MfaPolicyService policy;

    public MfaPolicyController(final MfaPolicyService policy) {
        this.policy = policy;
    }

    @GetMapping
    public ResponseEntity<MfaPolicyService.Policy> get(@PathVariable final String realmId) {
        return policy.get(realmId).map(ResponseEntity::ok).orElseGet(() -> ResponseEntity.notFound().build());
    }

    @PutMapping
    public ResponseEntity<MfaPolicyService.Policy> put(@PathVariable final String realmId, @Valid @RequestBody final Body body) {
        return policy.update(realmId, body.requireMfa(), body.skipGraceDays()).map(ResponseEntity::ok)
                .orElseGet(() -> ResponseEntity.notFound().build());
    }

    public record Body(Boolean requireMfa,
                       @Min(value = 0, message = "Skip grace days cannot be negative.")
                       @Max(value = 90, message = "Skip grace days cannot exceed 90.") Integer skipGraceDays) {
    }
}
