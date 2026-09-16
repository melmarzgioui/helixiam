/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.amqp.audit.adapter;

import io.helixiam.authorization.amqp.audit.AuditLogPublisher;
import io.helixiam.authorization.amqp.audit.AuditPage;
import io.helixiam.authorization.amqp.audit.AuditQuery;
import io.helixiam.authorization.amqp.audit.AuditRecord;
import io.helixiam.authorization.amqp.support.DtoBridge;
import io.helixiam.authorization.service.audit.AuditLogService;
import org.springframework.stereotype.Component;

/**
 * Strip-RabbitMQ (Task 3): in-process adapter replacing the former AMQP transport of
 * {@link AuditLogPublisher}.
 */
@Component
public class AuditLogLocalAdapter implements AuditLogPublisher {

    private final AuditLogService service;
    private final DtoBridge bridge;

    public AuditLogLocalAdapter(final AuditLogService service, final DtoBridge bridge) {
        this.service = service;
        this.bridge = bridge;
    }

    @Override
    public Boolean record(final AuditRecord record) {
        service.record(bridge.to(record, io.helixiam.authorization.domain.audit.AuditRecord.class));
        return Boolean.TRUE;
    }

    @Override
    public AuditPage search(final AuditQuery query) {
        return bridge.to(service.search(
                bridge.to(query, io.helixiam.authorization.domain.audit.AuditQuery.class)),
                AuditPage.class);
    }
}
