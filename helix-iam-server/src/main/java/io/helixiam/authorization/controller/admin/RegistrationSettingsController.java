/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.controller.admin;

import io.helixiam.authorization.service.registration.RegistrationSettingsService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Item A8: the realm's self-registration return settings. {@code postRegistrationRedirectUrl} is where a user goes
 * after registering or verifying their email when no sign-in is pending (with one, they return to it); it must be on
 * one of the realm's registered redirect origins. PUT updates the fields present ({@code ""} clears); a URL on another
 * origin is a {@code 400 {message, fieldErrors}}. Needs {@code manage-realm} (the {@code settings} admin route).
 */
@RestController
@RequestMapping("/admin/realms/{realmId}/settings/registration")
public class RegistrationSettingsController {

    private final RegistrationSettingsService settings;

    public RegistrationSettingsController(final RegistrationSettingsService settings) {
        this.settings = settings;
    }

    @GetMapping
    public ResponseEntity<RegistrationSettingsService.Settings> get(@PathVariable final String realmId) {
        return settings.get(realmId).map(ResponseEntity::ok).orElseGet(() -> ResponseEntity.notFound().build());
    }

    @PutMapping
    public ResponseEntity<?> put(@PathVariable final String realmId, @RequestBody final Body body) {
        try {
            return settings.update(realmId, body.postRegistrationRedirectUrl()).<ResponseEntity<?>>map(ResponseEntity::ok)
                    .orElseGet(() -> ResponseEntity.notFound().build());
        } catch (final RegistrationSettingsService.InvalidRedirectException e) {
            final Map<String, Object> error = new LinkedHashMap<>();
            error.put("message", e.getMessage());
            error.put("fieldErrors", Map.of("postRegistrationRedirectUrl", e.getMessage()));
            return ResponseEntity.badRequest().body(error);
        }
    }

    public record Body(String postRegistrationRedirectUrl) {
    }
}
