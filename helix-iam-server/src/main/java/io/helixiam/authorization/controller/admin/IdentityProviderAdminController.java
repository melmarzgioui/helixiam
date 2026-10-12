/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.controller.admin;

import io.helixiam.authorization.amqp.federation.IdentityProviderConfig;
import io.helixiam.authorization.amqp.federation.IdentityProviderConfigPublisher;
import io.helixiam.authorization.amqp.federation.IdentityProviderRef;
import io.helixiam.authorization.federation.FederationProviderFactory;
import io.helixiam.authorization.federation.FederationStoreRefresher;
import io.helixiam.authorization.federation.ProviderSecretKeys;
import io.helixiam.authorization.federation.wallet.WalletConfigValidator;
import io.helixiam.common.log.LogSafe;
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

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Helix IAM E8.2: admin REST API for per-realm identity-provider connections — the backend behind the
 * console's "Add identity provider" wizard (DigiD / eHerkenning / eIDAS / OIDC / SAML / LDAP). The
 * realm is always taken from the path so a connection can only be written into its own realm; the
 * store is owned by the identity domain (subscriber) and reached over AMQP.
 *
 * <p>Task 4 (security): secrets ({@link ProviderSecretKeys}) are write-only. Responses carry
 * {@code "<key>Set": true|false} instead of the value ({@link IdentityProviderAdminView}); on a write an absent or blank
 * secret keeps the stored one, a value replaces it, and {@code "clear<Key>": "true"} removes it (like the messaging
 * provider's {@code clearSecret}). A value together with its clear flag is a 400.
 */
@RestController
@RequestMapping("/admin/realms/{realmId}/identity-providers")
public class IdentityProviderAdminController {

    private static final Logger LOG = LogManager.getLogger(IdentityProviderAdminController.class);

    private final IdentityProviderConfigPublisher publisher;
    /** E8.3: present only when helix.federation.store.enabled — refreshes the live registry after a write. */
    private final FederationStoreRefresher refresher;
    /** Task 19: checks EUDI wallet connections before they are saved; null skips (unit tests of other protocols). */
    private final WalletConfigValidator walletValidator;

    public IdentityProviderAdminController(final IdentityProviderConfigPublisher publisher) {
        this(publisher, (FederationStoreRefresher) null, (WalletConfigValidator) null);
    }

    /** Tests: wallet connections validated by {@code walletValidator}, no registry refresh. */
    public IdentityProviderAdminController(final IdentityProviderConfigPublisher publisher,
                                           final WalletConfigValidator walletValidator) {
        this(publisher, (FederationStoreRefresher) null, walletValidator);
    }

    @Autowired
    public IdentityProviderAdminController(final IdentityProviderConfigPublisher publisher,
                                           final ObjectProvider<FederationStoreRefresher> refresher,
                                           final ObjectProvider<WalletConfigValidator> walletValidator) {
        this(publisher, refresher.getIfAvailable(), walletValidator.getIfAvailable());
    }

    private IdentityProviderAdminController(final IdentityProviderConfigPublisher publisher,
                                            final FederationStoreRefresher refresher,
                                            final WalletConfigValidator walletValidator) {
        this.publisher = publisher;
        this.refresher = refresher;
        this.walletValidator = walletValidator;
    }

    @GetMapping
    public List<IdentityProviderAdminView> list(@PathVariable final String realmId) {
        return publisher.list(realmId).stream().map(IdentityProviderAdminView::of).toList();
    }

    @GetMapping("/{alias}")
    public ResponseEntity<IdentityProviderAdminView> get(@PathVariable final String realmId,
                                                      @PathVariable final String alias) {
        final IdentityProviderConfig config = publisher.get(new IdentityProviderRef(realmId, alias));
        return config == null ? ResponseEntity.notFound().build() : ResponseEntity.ok(IdentityProviderAdminView.of(config));
    }

    @PostMapping
    public ResponseEntity<IdentityProviderAdminView> create(@PathVariable final String realmId,
                                                         @Valid @RequestBody final IdentityProviderRequest request) {
        checkSecrets(request);
        checkWallet(realmId, request.alias(), request);
        final IdentityProviderConfig saved = publisher.save(toConfig(realmId, request.alias(), request));
        refresh(realmId);
        return ResponseEntity.status(HttpStatus.CREATED).body(IdentityProviderAdminView.of(saved));
    }

    @PutMapping("/{alias}")
    public ResponseEntity<IdentityProviderAdminView> update(@PathVariable final String realmId,
                                                         @PathVariable final String alias,
                                                         @Valid @RequestBody final IdentityProviderRequest request) {
        checkSecrets(request);
        checkWallet(realmId, alias, request);
        final IdentityProviderConfig saved = publisher.save(toConfig(realmId, alias, request));
        refresh(realmId);
        return ResponseEntity.ok(IdentityProviderAdminView.of(saved));
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
                    LogSafe.sanitize(realmId), LogSafe.sanitize(e.getMessage()));
        }
    }

    /** A new secret and its clear flag together are ambiguous: 400 {message, fieldErrors} (AdminValidationAdvice). */
    private static void checkSecrets(final IdentityProviderRequest request) {
        if (request.config() == null) {
            return;
        }
        final Map<String, String> errors = new LinkedHashMap<>();
        for (final String key : ProviderSecretKeys.allKeys()) {
            final String value = request.config().get(key);
            if (ProviderSecretKeys.clears(request.config(), key) && value != null && !value.isBlank()) {
                errors.put("config." + ProviderSecretKeys.clearFlag(key),
                        "Give a new " + key + " or clear the stored one, not both.");
            }
        }
        if (!errors.isEmpty()) {
            throw new ProviderValidationException(errors);
        }
    }

    /**
     * Task 19: an EUDI wallet connection is checked by {@link WalletConfigValidator#validateWrite} as it will be
     * stored (a secret left out of the write keeps the stored one, a clear flag removes it), and refused with
     * {@code 400 {message, fieldErrors}}: config fields as {@code config.<field>}, alias and display name as
     * themselves. Without the validator a wallet write is refused (fail closed), never saved unchecked.
     */
    private void checkWallet(final String realmId, final String alias, final IdentityProviderRequest request) {
        if (!FederationProviderFactory.isWallet(request.protocol())) {
            return;
        }
        if (walletValidator == null) {
            LOG.error("EUDI wallet connection {} in realm {} refused: no wallet config validator is available",
                    LogSafe.sanitize(alias), LogSafe.sanitize(realmId));
            throw new ProviderValidationException(Map.of("protocol",
                    "EUDI wallet connections cannot be validated on this server, so they cannot be saved."));
        }
        final Map<String, String> errors = WalletConfigValidator.asAdminFields(walletValidator.validateWrite(realmId,
                alias, request.displayName(), request.config(), storedConfig(realmId, alias)));
        if (!errors.isEmpty()) {
            throw new ProviderValidationException(errors);
        }
    }

    /** The stored connection's settings with its secrets (empty when there is none, or it cannot be read now). */
    private Map<String, String> storedConfig(final String realmId, final String alias) {
        try {
            final IdentityProviderConfig stored = publisher.get(new IdentityProviderRef(realmId, alias));
            return stored == null || stored.config() == null ? Map.of() : stored.config();
        } catch (final RuntimeException e) {
            LOG.warn("Could not read the stored identity provider {} in realm {} to validate the write: {}",
                    LogSafe.sanitize(alias), LogSafe.sanitize(realmId), LogSafe.sanitize(e.getMessage()));
            return Map.of();
        }
    }

    private static IdentityProviderConfig toConfig(final String realmId, final String alias,
                                                   final IdentityProviderRequest request) {
        // Task 19 carry-over: the protocol is stored trimmed and lower-case, so every lookup by protocol
        // (ProviderSecretKeys.keysFor, the provider factory, the console) sees the canonical value.
        return new IdentityProviderConfig(realmId, alias, request.protocol().trim().toLowerCase(Locale.ROOT),
                request.displayName(),
                request.enabled(), request.config() == null ? Map.of() : request.config());
    }
}
