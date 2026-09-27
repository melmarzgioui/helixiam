/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.controller.admin;

import io.helixiam.authorization.service.account.AccountConsoleSettings;
import io.helixiam.authorization.service.account.AccountConsoleSettingsService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * B1: admin API for what the realm's account console allows ({@link AccountConsoleSettings}). Lives under
 * {@code settings} so the admin RBAC maps it to manage-realm (reads to view-realm).
 */
@RestController
@RequestMapping("/admin/realms/{realmId}/settings/account-console")
public class AccountConsoleSettingsController {

    private final AccountConsoleSettingsService service;

    public AccountConsoleSettingsController(final AccountConsoleSettingsService service) {
        this.service = service;
    }

    @GetMapping
    public ResponseEntity<AccountConsoleSettings> get(@PathVariable final String realmId) {
        return service.find(realmId).map(ResponseEntity::ok).orElseGet(() -> ResponseEntity.notFound().build());
    }

    /** Replaces the settings; a field left out takes its default. */
    @PutMapping
    public ResponseEntity<AccountConsoleSettings> put(@PathVariable final String realmId,
                                                      @RequestBody(required = false) final AccountConsoleSettings body) {
        return service.replace(realmId, body).map(ResponseEntity::ok).orElseGet(() -> ResponseEntity.notFound().build());
    }
}
