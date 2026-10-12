/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.controller.admin;

import io.helixiam.authorization.security.audit.AuditContext;
import io.helixiam.authorization.service.key.KeyImportException;
import io.helixiam.authorization.service.key.RealmSigningKeys;
import io.helixiam.authorization.service.key.SigningKeyHandle;
import io.helixiam.authorization.service.key.SigningKeySummary;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

/**
 * Task 24: the realm's verifier access keys (the EUDI wallet provider's {@code accessKeyRef}) for the admin console.
 * {@code POST} imports a PEM private key and its chain into the software key store (DB-encrypted) and answers with the
 * key reference and the leaf's public facts; {@code GET} lists them. The private key is write-only: it is never
 * returned, logged or audited.
 *
 * <p>Conventions: the realm comes from the path; access needs {@code manage-identity-providers}
 * ({@code AdminRoutePermissions}, group {@code verifier-keys}); writes need the CSRF header like every admin write;
 * the import is audited as {@code VERIFIER_KEY_IMPORT} (with the key name and reference as detail). Every refusal of
 * the store ({@link KeyImportException}: bad PEM, wrong curve, RSA, self-signed leaf, chain order, a taken name, no
 * {@code DB_ENCRYPTION} outside dev) is a {@code 400 {message, fieldErrors}} on the form field it names, never a 500.
 */
@RestController
@RequestMapping("/admin/realms/{realmId}/verifier-keys")
public class VerifierKeyAdminController {

    private final RealmSigningKeys keys;

    public VerifierKeyAdminController(final RealmSigningKeys keys) {
        this.keys = keys;
    }

    @GetMapping
    public List<VerifierKeyView> list(@PathVariable final String realmId) {
        return keys.list(realmId).stream().map(VerifierKeyView::of).toList();
    }

    @PostMapping
    public ResponseEntity<VerifierKeyView> importKey(@PathVariable final String realmId,
                                                     @Valid @RequestBody final VerifierKeyImportRequest request,
                                                     final HttpServletRequest http) {
        final String keyRef;
        try {
            keyRef = keys.importKey(realmId, request.name(), request.privateKeyPem(), request.certificateChainPem());
        } catch (final KeyImportException e) {
            throw new ProviderValidationException(Map.of(e.field(), message(e)));
        } catch (final IllegalArgumentException e) {
            // The interface contract only promises an IllegalArgumentException; its message is field-safe.
            throw new ProviderValidationException(Map.of(KeyImportException.CHAIN, message(e)));
        }
        AuditContext.attachDetail(http, Map.of("name", request.name(), "keyRef", keyRef));
        return ResponseEntity.status(HttpStatus.CREATED).body(VerifierKeyView.of(stored(realmId, request.name(), keyRef)));
    }

    /** The imported key as listed (with its import time), or from its handle for a store that does not list. */
    private SigningKeySummary stored(final String realmId, final String name, final String keyRef) {
        return keys.list(realmId).stream().filter(k -> keyRef.equals(k.keyRef())).findFirst().orElseGet(() -> {
            final SigningKeyHandle handle = keys.resolve(realmId, keyRef);
            return new SigningKeySummary(keyRef, name, handle.algorithm().getName(), handle.certificateChain(), null);
        });
    }

    private static String message(final IllegalArgumentException e) {
        return e.getMessage() == null || e.getMessage().isBlank() ? "The key could not be imported." : e.getMessage();
    }
}
