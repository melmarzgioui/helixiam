/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.controller.admin;

import io.helixiam.authorization.amqp.webhook.WebhookConfigPublisher;
import io.helixiam.authorization.amqp.webhook.WebhookRef;
import io.helixiam.authorization.amqp.webhook.WebhookSubscriptionDto;
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
 * Helix IAM B6: admin REST API for per-realm outbound webhooks — the backend behind the console's
 * Webhooks screen. The realm comes from the path. The signing secret is write-only: it is never
 * returned (only {@code secretSet} indicates one exists), and a blank secret on update preserves it.
 */
@RestController
@RequestMapping("/admin/realms/{realmId}/webhooks")
public class WebhookAdminController {

    private final WebhookConfigPublisher publisher;

    public WebhookAdminController(final WebhookConfigPublisher publisher) {
        this.publisher = publisher;
    }

    /** Editable webhook payload from the console (realm + id come from the path). */
    public record WebhookRequest(String name, @NotBlank(message = "URL is required.") String url, String secret,
                                 String eventTypes, Boolean enabled) {
    }

    @GetMapping
    public List<WebhookSubscriptionDto> list(@PathVariable final String realmId) {
        return publisher.list(realmId).stream().map(WebhookAdminController::withoutSecret).toList();
    }

    @PostMapping
    public ResponseEntity<WebhookSubscriptionDto> create(@PathVariable final String realmId,
                                                         @Valid @RequestBody final WebhookRequest body) {
        final WebhookSubscriptionDto saved = publisher.save(new WebhookSubscriptionDto(null, realmId, body.name(),
                body.url(), body.secret(), false, body.eventTypes(), body.enabled() == null || body.enabled(), null));
        return ResponseEntity.status(HttpStatus.CREATED).body(withoutSecret(saved));
    }

    @PutMapping("/{id}")
    public ResponseEntity<WebhookSubscriptionDto> update(@PathVariable final String realmId, @PathVariable final String id,
                                                         @Valid @RequestBody final WebhookRequest body) {
        final WebhookSubscriptionDto saved = publisher.save(new WebhookSubscriptionDto(id, realmId, body.name(),
                body.url(), body.secret(), false, body.eventTypes(), body.enabled() == null || body.enabled(), null));
        return ResponseEntity.ok(withoutSecret(saved));
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Void> delete(@PathVariable final String realmId, @PathVariable final String id) {
        final boolean removed = Boolean.TRUE.equals(publisher.delete(new WebhookRef(realmId, id)));
        return removed ? ResponseEntity.noContent().build() : ResponseEntity.notFound().build();
    }

    /** Nulls the write-only signing secret so it never reaches the browser; {@code secretSet} is kept. */
    private static WebhookSubscriptionDto withoutSecret(final WebhookSubscriptionDto d) {
        return new WebhookSubscriptionDto(d.id(), d.realmId(), d.name(), d.url(), null, d.secretSet(),
                d.eventTypes(), d.enabled(), d.createdAt());
    }
}
