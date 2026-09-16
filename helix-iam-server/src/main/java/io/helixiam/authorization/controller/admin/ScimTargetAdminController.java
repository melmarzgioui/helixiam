/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.controller.admin;

import io.helixiam.authorization.amqp.scim.ScimTargetConfigPublisher;
import io.helixiam.authorization.amqp.scim.ScimTargetDto;
import io.helixiam.authorization.amqp.scim.ScimTargetRef;
import io.swagger.v3.oas.annotations.tags.Tag;
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
 * Helix IAM B7: admin REST API for per-realm outbound SCIM provisioning targets — the backend behind the
 * console's Provisioning screen. The realm comes from the path. The bearer token is write-only: never
 * returned (only {@code tokenSet} indicates one exists), and a blank token on update preserves it.
 */
@RestController
@RequestMapping("/admin/realms/{realmId}/scim-targets")
@Tag(name = "Outbound SCIM", description = "Per-realm outbound SCIM 2.0 provisioning targets (push user lifecycle downstream).")
public class ScimTargetAdminController {

    private final ScimTargetConfigPublisher publisher;

    public ScimTargetAdminController(final ScimTargetConfigPublisher publisher) {
        this.publisher = publisher;
    }

    /** Editable SCIM-target payload from the console (realm + id come from the path). */
    public record ScimTargetRequest(String name, @NotBlank(message = "SCIM base URL is required.") String baseUrl,
                                     String token, String eventTypes, Boolean enabled) {
    }

    @GetMapping
    public List<ScimTargetDto> list(@PathVariable final String realmId) {
        return publisher.list(realmId).stream().map(ScimTargetAdminController::withoutToken).toList();
    }

    @PostMapping
    public ResponseEntity<ScimTargetDto> create(@PathVariable final String realmId,
                                                @Valid @RequestBody final ScimTargetRequest body) {
        final ScimTargetDto saved = publisher.save(new ScimTargetDto(null, realmId, body.name(), body.baseUrl(),
                body.token(), false, body.eventTypes(), body.enabled() == null || body.enabled(), null));
        return ResponseEntity.status(HttpStatus.CREATED).body(withoutToken(saved));
    }

    @PutMapping("/{id}")
    public ResponseEntity<ScimTargetDto> update(@PathVariable final String realmId, @PathVariable final String id,
                                                @Valid @RequestBody final ScimTargetRequest body) {
        final ScimTargetDto saved = publisher.save(new ScimTargetDto(id, realmId, body.name(), body.baseUrl(),
                body.token(), false, body.eventTypes(), body.enabled() == null || body.enabled(), null));
        return ResponseEntity.ok(withoutToken(saved));
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Void> delete(@PathVariable final String realmId, @PathVariable final String id) {
        final boolean removed = Boolean.TRUE.equals(publisher.delete(new ScimTargetRef(realmId, id)));
        return removed ? ResponseEntity.noContent().build() : ResponseEntity.notFound().build();
    }

    /** Nulls the write-only bearer token so it never reaches the browser; {@code tokenSet} is kept. */
    private static ScimTargetDto withoutToken(final ScimTargetDto d) {
        return new ScimTargetDto(d.id(), d.realmId(), d.name(), d.baseUrl(), null, d.tokenSet(),
                d.eventTypes(), d.enabled(), d.createdAt());
    }
}
