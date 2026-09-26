/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.controller.admin;

import io.helixiam.authorization.service.account.SelfEditableAttributesService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;
import java.util.Set;

/**
 * 1.0 security (item 1): admin API for the realm's self-editable profile attributes. Lives under
 * {@code settings} so the admin RBAC maps it to manage-realm.
 */
@RestController
@RequestMapping("/admin/realms/{realmId}/settings/self-editable-attributes")
public class SelfEditableAttributesController {

    private final SelfEditableAttributesService service;

    public SelfEditableAttributesController(final SelfEditableAttributesService service) {
        this.service = service;
    }

    public record Body(Set<String> attributes) {
    }

    @GetMapping
    public Body get(@PathVariable final String realmId) {
        return new Body(service.allowed(realmId));
    }

    @PutMapping
    public ResponseEntity<?> put(@PathVariable final String realmId, @RequestBody final Body body) {
        final Set<String> reserved = SelfEditableAttributesService.reserved(body == null ? null : body.attributes());
        if (!reserved.isEmpty()) {
            return ResponseEntity.badRequest().body(Map.of(
                    "message", "Reserved claim names can never be self-editable: " + String.join(", ", reserved),
                    "fieldErrors", Map.of("attributes", "Reserved claim names are not allowed.")));
        }
        return service.replace(realmId, body == null ? null : body.attributes())
                .<ResponseEntity<?>>map(saved -> ResponseEntity.ok(new Body(saved)))
                .orElseGet(() -> ResponseEntity.notFound().build());
    }
}
