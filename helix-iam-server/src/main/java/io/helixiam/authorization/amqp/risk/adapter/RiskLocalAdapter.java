/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.amqp.risk.adapter;

import io.helixiam.authorization.amqp.risk.RiskLoginRecord;
import io.helixiam.authorization.amqp.risk.RiskPublisher;
import io.helixiam.authorization.amqp.risk.RiskSignalRequest;
import io.helixiam.authorization.amqp.risk.RiskSignals;
import io.helixiam.authorization.amqp.support.DtoBridge;
import io.helixiam.authorization.service.risk.RiskHistoryService;
import org.springframework.stereotype.Component;

/**
 * Strip-RabbitMQ (Task 3): in-process adapter replacing the former AMQP transport of
 * {@link RiskPublisher}.
 */
@Component
public class RiskLocalAdapter implements RiskPublisher {

    private final RiskHistoryService riskHistoryService;
    private final DtoBridge bridge;

    public RiskLocalAdapter(final RiskHistoryService riskHistoryService, final DtoBridge bridge) {
        this.riskHistoryService = riskHistoryService;
        this.bridge = bridge;
    }

    @Override
    public RiskSignals evaluateSignals(final RiskSignalRequest request) {
        return bridge.to(riskHistoryService.evaluate(
                bridge.to(request, io.helixiam.authorization.domain.risk.RiskSignalRequest.class)),
                RiskSignals.class);
    }

    @Override
    public Boolean recordLogin(final RiskLoginRecord record) {
        riskHistoryService.record(
                bridge.to(record, io.helixiam.authorization.domain.risk.RiskLoginRecord.class));
        return Boolean.TRUE;
    }
}
