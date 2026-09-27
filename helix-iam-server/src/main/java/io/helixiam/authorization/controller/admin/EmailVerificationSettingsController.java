/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.controller.admin;

import io.helixiam.authorization.service.emailverification.EmailVerificationService;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * C3: whether a realm requires a verified email address before it issues tokens (off by default). When on, a user
 * with an unverified address is held at sign-in until they open the emailed link, and token requests for them are
 * refused with {@code access_denied}. Users without an email address are not affected.
 */
@RestController
@RequestMapping("/admin/realms/{realmId}/settings/verify-email")
public class EmailVerificationSettingsController {

    private final EmailVerificationService verification;

    public EmailVerificationSettingsController(final EmailVerificationService verification) {
        this.verification = verification;
    }

    @GetMapping
    public Body get(@PathVariable final String realmId) {
        return new Body(verification.realmRequires(realmId));
    }

    @PutMapping
    public ResponseEntity<Body> put(@PathVariable final String realmId, @Valid @RequestBody final Body body) {
        return verification.setRealmRequires(realmId, body.enabled()).map(e -> ResponseEntity.ok(new Body(e)))
                .orElseGet(() -> ResponseEntity.notFound().build());
    }

    public record Body(@NotNull(message = "enabled is required.") Boolean enabled) {
    }
}
