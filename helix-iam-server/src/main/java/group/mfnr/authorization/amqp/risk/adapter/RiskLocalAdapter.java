package group.mfnr.authorization.amqp.risk.adapter;

import group.mfnr.authorization.amqp.risk.RiskLoginRecord;
import group.mfnr.authorization.amqp.risk.RiskPublisher;
import group.mfnr.authorization.amqp.risk.RiskSignalRequest;
import group.mfnr.authorization.amqp.risk.RiskSignals;
import group.mfnr.authorization.amqp.support.DtoBridge;
import group.mfnr.authorization.service.risk.RiskHistoryService;
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
                bridge.to(request, group.mfnr.authorization.domain.risk.RiskSignalRequest.class)),
                RiskSignals.class);
    }

    @Override
    public Boolean recordLogin(final RiskLoginRecord record) {
        riskHistoryService.record(
                bridge.to(record, group.mfnr.authorization.domain.risk.RiskLoginRecord.class));
        return Boolean.TRUE;
    }
}
