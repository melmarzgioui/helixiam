/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.controller.admin;

import io.helixiam.authorization.service.client.TokenExchangePolicyService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Set;

/**
 * 1.0 item 5: which clients may exchange tokens for this client ({@code audience=<clientId>}). {@code clientId}
 * in the path is the OAuth client id. 404 when the client is not in the realm.
 */
@RestController
@RequestMapping("/admin/realms/{realmId}/clients/{clientId}/token-exchange")
public class TokenExchangePolicyController {

    private final TokenExchangePolicyService service;

    public TokenExchangePolicyController(final TokenExchangePolicyService service) {
        this.service = service;
    }

    @GetMapping
    public ResponseEntity<Policy> get(@PathVariable final String realmId, @PathVariable final String clientId) {
        return service.allowedClients(realmId, clientId).map(a -> ResponseEntity.ok(new Policy(a)))
                .orElseGet(() -> ResponseEntity.notFound().build());
    }

    @PutMapping
    public ResponseEntity<Policy> put(@PathVariable final String realmId, @PathVariable final String clientId,
                                      @RequestBody final Policy body) {
        return service.replace(realmId, clientId, body == null ? Set.of() : body.allowedClients())
                .map(a -> ResponseEntity.ok(new Policy(a)))
                .orElseGet(() -> ResponseEntity.notFound().build());
    }

    public record Policy(Set<String> allowedClients) {
    }
}
