/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.controller.admin;

import io.helixiam.authorization.amqp.application.ApplicationConfig;
import io.helixiam.authorization.amqp.application.ApplicationConfigPublisher;
import io.helixiam.authorization.amqp.application.ApplicationRef;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/**
 * Helix IAM: admin REST API for per-realm Applications (Service Providers) — the protocol-agnostic top
 * level that owns the shared subject claim + login flow. The OIDC client and SAML relying party link UP
 * to an application via their own {@code applicationId}; this controller manages the application itself.
 * Mirrors {@code SamlRelyingPartyAdminController}.
 */
@RestController
@RequestMapping("/admin/realms/{realmId}/applications")
public class ApplicationAdminController {

    private final ApplicationConfigPublisher publisher;

    public ApplicationAdminController(final ApplicationConfigPublisher publisher) {
        this.publisher = publisher;
    }

    @GetMapping
    public List<ApplicationConfig> list(@PathVariable final String realmId) {
        return publisher.list(realmId);
    }

    @GetMapping("/{name}")
    public ResponseEntity<ApplicationConfig> get(@PathVariable final String realmId, @PathVariable final String name) {
        final ApplicationConfig config = publisher.get(new ApplicationRef(realmId, name));
        return config == null ? ResponseEntity.notFound().build() : ResponseEntity.ok(config);
    }

    @PostMapping
    public ResponseEntity<ApplicationConfig> create(@PathVariable final String realmId,
                                                    @Valid @RequestBody final ApplicationRequest request) {
        final ApplicationConfig saved = publisher.save(toConfig(realmId, request.name(), request));
        return ResponseEntity.status(HttpStatus.CREATED).body(saved);
    }

    @PutMapping("/{name}")
    public ResponseEntity<ApplicationConfig> update(@PathVariable final String realmId, @PathVariable final String name,
                                                    @Valid @RequestBody final ApplicationRequest request) {
        final ApplicationConfig saved = publisher.save(toConfig(realmId, name, request));
        return ResponseEntity.ok(saved);
    }

    @DeleteMapping("/{name}")
    public ResponseEntity<Void> delete(@PathVariable final String realmId, @PathVariable final String name) {
        final boolean removed = Boolean.TRUE.equals(publisher.delete(new ApplicationRef(realmId, name)));
        return removed ? ResponseEntity.noContent().build() : ResponseEntity.notFound().build();
    }

    private static ApplicationConfig toConfig(final String realmId, final String name, final ApplicationRequest request) {
        return new ApplicationConfig(realmId, name, request.description(), request.subjectClaim(),
                request.authFlowAlias(), request.enabled() == null || request.enabled(), request.displayName());
    }
}
