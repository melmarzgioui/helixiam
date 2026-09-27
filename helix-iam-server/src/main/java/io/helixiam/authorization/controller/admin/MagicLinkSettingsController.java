/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.controller.admin;

import io.helixiam.authorization.service.magiclink.MagicLinkService;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/** 1.0 item 6: switch passwordless magic-link sign-in on or off for a realm (off by default). */
@RestController
@RequestMapping("/admin/realms/{realmId}/settings/magic-link")
public class MagicLinkSettingsController {

    private final MagicLinkService magicLinks;

    public MagicLinkSettingsController(final MagicLinkService magicLinks) {
        this.magicLinks = magicLinks;
    }

    @GetMapping
    public Body get(@PathVariable final String realmId) {
        return new Body(magicLinks.enabled(realmId));
    }

    @PutMapping
    public ResponseEntity<Body> put(@PathVariable final String realmId, @Valid @RequestBody final Body body) {
        return magicLinks.setEnabled(realmId, body.enabled()).map(e -> ResponseEntity.ok(new Body(e)))
                .orElseGet(() -> ResponseEntity.notFound().build());
    }

    public record Body(@NotNull(message = "enabled is required.") Boolean enabled) {
    }
}
