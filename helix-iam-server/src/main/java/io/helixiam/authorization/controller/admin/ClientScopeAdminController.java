/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.controller.admin;

import io.helixiam.authorization.amqp.scope.ClaimScopePublisher;
import io.helixiam.authorization.amqp.scope.ClientScopeDto;
import io.helixiam.authorization.amqp.scope.ScopeDetailDto;
import io.helixiam.authorization.amqp.scope.ScopeRef;
import io.helixiam.authorization.amqp.scope.ScopeWriteDto;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
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
 * Helix IAM E8.5: admin REST API for a realm's client scopes — the table behind the Client scopes
 * screen, the scope detail page, and the add/remove-claim actions. Realm comes from the path.
 */
@RestController
@RequestMapping("/admin/realms/{realmId}/client-scopes")
public class ClientScopeAdminController {

    private final ClaimScopePublisher publisher;

    public ClientScopeAdminController(final ClaimScopePublisher publisher) {
        this.publisher = publisher;
    }

    @GetMapping
    public List<ClientScopeDto> list(@PathVariable final String realmId) {
        return publisher.scopes(realmId);
    }

    @GetMapping("/{scopeId}")
    public ResponseEntity<ScopeDetailDto> get(@PathVariable final String realmId, @PathVariable final String scopeId) {
        final ScopeDetailDto detail = publisher.scope(new ScopeRef(realmId, scopeId, null));
        return detail == null ? ResponseEntity.notFound().build() : ResponseEntity.ok(detail);
    }

    @PostMapping
    public ResponseEntity<ClientScopeDto> create(@PathVariable final String realmId, @Valid @RequestBody final ScopeRequest request) {
        final ClientScopeDto saved = publisher.createScope(new ScopeWriteDto(realmId, request.name(), request.description()));
        return ResponseEntity.status(HttpStatus.CREATED).body(saved);
    }

    @DeleteMapping("/{scopeId}")
    public ResponseEntity<Void> delete(@PathVariable final String realmId, @PathVariable final String scopeId) {
        return Boolean.TRUE.equals(publisher.deleteScope(new ScopeRef(realmId, scopeId, null)))
                ? ResponseEntity.noContent().build() : ResponseEntity.notFound().build();
    }

    @PutMapping("/{scopeId}/claims/{claimId}")
    public ResponseEntity<Void> addClaim(@PathVariable final String realmId, @PathVariable final String scopeId,
                                         @PathVariable final String claimId) {
        return Boolean.TRUE.equals(publisher.addClaim(new ScopeRef(realmId, scopeId, claimId)))
                ? ResponseEntity.noContent().build() : ResponseEntity.notFound().build();
    }

    @DeleteMapping("/{scopeId}/claims/{claimId}")
    public ResponseEntity<Void> removeClaim(@PathVariable final String realmId, @PathVariable final String scopeId,
                                            @PathVariable final String claimId) {
        return Boolean.TRUE.equals(publisher.removeClaim(new ScopeRef(realmId, scopeId, claimId)))
                ? ResponseEntity.noContent().build() : ResponseEntity.notFound().build();
    }

    /** Create body for a client scope. */
    public record ScopeRequest(@NotBlank(message = "Scope name is required.") String name, String description) {
    }
}
