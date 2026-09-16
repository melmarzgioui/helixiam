/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.controller.admin;

import io.helixiam.authorization.amqp.federation.IdentityProviderConfig;
import io.helixiam.authorization.amqp.federation.IdentityProviderConfigPublisher;
import io.helixiam.authorization.amqp.federation.IdentityProviderRef;
import io.helixiam.authorization.federation.FederationStoreRefresher;
import jakarta.validation.Valid;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Autowired;
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
import java.util.Map;

/**
 * Helix IAM E8.2: admin REST API for per-realm identity-provider connections — the backend behind the
 * console's "Add identity provider" wizard (DigiD / eHerkenning / eIDAS / OIDC / SAML / LDAP). The
 * realm is always taken from the path so a connection can only be written into its own realm; the
 * store is owned by the identity domain (subscriber) and reached over AMQP.
 */
@RestController
@RequestMapping("/admin/realms/{realmId}/identity-providers")
public class IdentityProviderAdminController {

    private static final Logger LOG = LogManager.getLogger(IdentityProviderAdminController.class);

    private final IdentityProviderConfigPublisher publisher;
    /** E8.3: present only when helix.federation.store.enabled — refreshes the live registry after a write. */
    private final FederationStoreRefresher refresher;

    public IdentityProviderAdminController(final IdentityProviderConfigPublisher publisher) {
        this(publisher, (FederationStoreRefresher) null);
    }

    @Autowired
    public IdentityProviderAdminController(final IdentityProviderConfigPublisher publisher,
                                           final ObjectProvider<FederationStoreRefresher> refresher) {
        this(publisher, refresher.getIfAvailable());
    }

    private IdentityProviderAdminController(final IdentityProviderConfigPublisher publisher,
                                            final FederationStoreRefresher refresher) {
        this.publisher = publisher;
        this.refresher = refresher;
    }

    @GetMapping
    public List<IdentityProviderConfig> list(@PathVariable final String realmId) {
        return publisher.list(realmId);
    }

    @GetMapping("/{alias}")
    public ResponseEntity<IdentityProviderConfig> get(@PathVariable final String realmId,
                                                      @PathVariable final String alias) {
        final IdentityProviderConfig config = publisher.get(new IdentityProviderRef(realmId, alias));
        return config == null ? ResponseEntity.notFound().build() : ResponseEntity.ok(config);
    }

    @PostMapping
    public ResponseEntity<IdentityProviderConfig> create(@PathVariable final String realmId,
                                                         @Valid @RequestBody final IdentityProviderRequest request) {
        final IdentityProviderConfig saved = publisher.save(toConfig(realmId, request.alias(), request));
        refresh(realmId);
        return ResponseEntity.status(HttpStatus.CREATED).body(saved);
    }

    @PutMapping("/{alias}")
    public ResponseEntity<IdentityProviderConfig> update(@PathVariable final String realmId,
                                                         @PathVariable final String alias,
                                                         @Valid @RequestBody final IdentityProviderRequest request) {
        final IdentityProviderConfig saved = publisher.save(toConfig(realmId, alias, request));
        refresh(realmId);
        return ResponseEntity.ok(saved);
    }

    @DeleteMapping("/{alias}")
    public ResponseEntity<Void> delete(@PathVariable final String realmId, @PathVariable final String alias) {
        final boolean removed = Boolean.TRUE.equals(publisher.delete(new IdentityProviderRef(realmId, alias)));
        if (removed) {
            refresh(realmId);
        }
        return removed ? ResponseEntity.noContent().build() : ResponseEntity.notFound().build();
    }

    /** E8.3: reload the live registry so a console change takes effect without a restart (best-effort). */
    private void refresh(final String realmId) {
        if (refresher == null) {
            return;
        }
        try {
            refresher.refresh(realmId);
        } catch (final RuntimeException e) {
            LOG.warn("Identity-provider registry refresh failed for realm {} (change persisted): {}",
                    realmId, e.getMessage());
        }
    }

    private static IdentityProviderConfig toConfig(final String realmId, final String alias,
                                                   final IdentityProviderRequest request) {
        return new IdentityProviderConfig(realmId, alias, request.protocol(), request.displayName(),
                request.enabled(), request.config() == null ? Map.of() : request.config());
    }
}
