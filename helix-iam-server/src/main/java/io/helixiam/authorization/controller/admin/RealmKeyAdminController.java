/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.controller.admin;

import io.helixiam.authorization.amqp.key.RealmKeyConfigPublisher;
import io.helixiam.authorization.amqp.key.RealmKeyView;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/**
 * Helix IAM B8: admin REST API for per-realm JWT signing keys — the backend behind the console's
 * "Realm keys" screen. The realm is always taken from the path. The key store is owned by the
 * identity domain (subscriber) and reached over AMQP; the per-realm JWKS reads the same store, so a
 * rotation here takes effect with no restart (old key stays published until retired → zero downtime).
 * Mirrors {@code SamlRelyingPartyAdminController}.
 */
@RestController
@RequestMapping("/admin/realms/{realmId}/keys")
public class RealmKeyAdminController {

    private final RealmKeyConfigPublisher publisher;

    public RealmKeyAdminController(final RealmKeyConfigPublisher publisher) {
        this.publisher = publisher;
    }

    /** All keys for the realm (ACTIVE/ROTATED/RETIRED), newest first. */
    @GetMapping
    public List<RealmKeyView> list(@PathVariable final String realmId) {
        return publisher.list(realmId);
    }

    /** Rotate the realm's active signing key; returns the new ACTIVE key. */
    @PostMapping("/rotate")
    public RealmKeyView rotate(@PathVariable final String realmId) {
        return publisher.rotate(realmId);
    }

    /** Retire a (rotated) key so it drops out of the published JWKS. 404 if the key id is unknown. */
    @DeleteMapping("/{keyId}")
    public ResponseEntity<Void> retire(@PathVariable final String realmId, @PathVariable final String keyId) {
        final Boolean retired = publisher.retire(keyId);
        return Boolean.TRUE.equals(retired) ? ResponseEntity.noContent().build() : ResponseEntity.notFound().build();
    }
}
