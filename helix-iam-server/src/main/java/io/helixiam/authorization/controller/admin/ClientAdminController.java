/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.controller.admin;

import io.helixiam.authorization.amqp.client.ClientAdminPublisher;
import io.helixiam.authorization.amqp.client.ClientDto;
import io.helixiam.authorization.amqp.client.ClientRef;
import io.helixiam.authorization.amqp.client.ClientWriteDto;
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
 * Helix IAM E8.5-S3: admin REST API for a realm's OAuth clients (relying parties) — the backend behind
 * the console's Clients screen. Secrets are write-only / returned once; realm comes from the path.
 */
@RestController
@RequestMapping("/admin/realms/{realmId}/clients")
public class ClientAdminController {

    private final ClientAdminPublisher publisher;

    public ClientAdminController(final ClientAdminPublisher publisher) {
        this.publisher = publisher;
    }

    @GetMapping
    public List<ClientDto> list(@PathVariable final String realmId) {
        return publisher.list(realmId);
    }

    @GetMapping("/{id}")
    public ResponseEntity<ClientDto> get(@PathVariable final String realmId, @PathVariable final String id) {
        final ClientDto client = publisher.get(new ClientRef(realmId, id));
        return client == null ? ResponseEntity.notFound().build() : ResponseEntity.ok(client);
    }

    @PostMapping
    public ResponseEntity<ClientDto> create(@PathVariable final String realmId, @Valid @RequestBody final ClientRequest request) {
        final ClientDto saved = publisher.create(new ClientWriteDto(realmId, null, request.clientId(),
                request.grantTypes(), request.redirectUris(), request.scopes(), request.subjectClaim(),
                request.authFlowAlias(), request.name(), request.description(), request.postLogoutRedirectUris(),
                request.webOrigins(), request.publicClient(), request.consentRequired(), request.displayOnConsentScreen(),
                request.loginTheme(), request.rootUrl(), request.homeUrl(), request.adminUrl(),
                request.alwaysDisplayInConsole(), request.accessTokenLifespan(), request.refreshTokenLifespan(),
                request.idTokenSignatureAlg(), request.reuseRefreshTokens(),
                request.tokenEndpointAuthMethod(), request.jwksUrl(),
                request.backchannelLogoutUri(), request.frontchannelLogoutUri(), request.applicationId(),
                request.x509CertificateBoundAccessTokens(), request.requireSignedRequestObject(),
                request.jarmResponseMode()));
        return ResponseEntity.status(HttpStatus.CREATED).body(saved);
    }

    @PutMapping("/{id}")
    public ResponseEntity<ClientDto> update(@PathVariable final String realmId, @PathVariable final String id,
                                            @Valid @RequestBody final ClientRequest request) {
        final ClientDto saved = publisher.update(new ClientWriteDto(realmId, id, request.clientId(),
                request.grantTypes(), request.redirectUris(), request.scopes(), request.subjectClaim(),
                request.authFlowAlias(), request.name(), request.description(), request.postLogoutRedirectUris(),
                request.webOrigins(), request.publicClient(), request.consentRequired(), request.displayOnConsentScreen(),
                request.loginTheme(), request.rootUrl(), request.homeUrl(), request.adminUrl(),
                request.alwaysDisplayInConsole(), request.accessTokenLifespan(), request.refreshTokenLifespan(),
                request.idTokenSignatureAlg(), request.reuseRefreshTokens(),
                request.tokenEndpointAuthMethod(), request.jwksUrl(),
                request.backchannelLogoutUri(), request.frontchannelLogoutUri(), request.applicationId(),
                request.x509CertificateBoundAccessTokens(), request.requireSignedRequestObject(),
                request.jarmResponseMode()));
        return saved == null ? ResponseEntity.notFound().build() : ResponseEntity.ok(saved);
    }

    @PostMapping("/{id}/secret")
    public ResponseEntity<ClientDto> regenerate(@PathVariable final String realmId, @PathVariable final String id) {
        final ClientDto rotated = publisher.regenerate(new ClientRef(realmId, id));
        return rotated == null ? ResponseEntity.notFound().build() : ResponseEntity.ok(rotated);
    }

    /** Reveals the client's current secret (Credentials tab); {@code secret} is populated. */
    @GetMapping("/{id}/secret")
    public ResponseEntity<ClientDto> reveal(@PathVariable final String realmId, @PathVariable final String id) {
        final ClientDto client = publisher.reveal(new ClientRef(realmId, id));
        return client == null ? ResponseEntity.notFound().build() : ResponseEntity.ok(client);
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Void> delete(@PathVariable final String realmId, @PathVariable final String id) {
        final boolean removed = Boolean.TRUE.equals(publisher.delete(new ClientRef(realmId, id)));
        return removed ? ResponseEntity.noContent().build() : ResponseEntity.notFound().build();
    }
}
