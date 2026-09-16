/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.controller.admin;

import io.helixiam.authorization.amqp.audit.AuditLogPublisher;
import io.helixiam.authorization.amqp.audit.AuditPage;
import io.helixiam.authorization.amqp.audit.AuditQuery;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * Helix IAM B3: searchable, paged audit-event history for the console's Events screen. Reads the
 * persisted audit log (owned by the subscriber) over the queue; complements the existing read-only
 * SIEM-delivery config endpoint. Realm-scoped; filters are optional.
 */
@RestController
public class EventsController {

    private final AuditLogPublisher publisher;

    public EventsController(final AuditLogPublisher publisher) {
        this.publisher = publisher;
    }

    @GetMapping("/admin/realms/{realm}/events")
    public AuditPage events(@PathVariable("realm") final String realm,
                            @RequestParam(value = "type", required = false) final String type,
                            @RequestParam(value = "actor", required = false) final String actor,
                            @RequestParam(value = "outcome", required = false) final String outcome,
                            @RequestParam(value = "category", required = false) final String category,
                            @RequestParam(value = "page", defaultValue = "0") final int page,
                            @RequestParam(value = "size", defaultValue = "50") final int size) {
        final AuditPage result = publisher.search(new AuditQuery(realm, type, actor, outcome, category, page, size));
        return result != null ? result : new AuditPage(java.util.List.of(), 0, page, size);
    }
}
