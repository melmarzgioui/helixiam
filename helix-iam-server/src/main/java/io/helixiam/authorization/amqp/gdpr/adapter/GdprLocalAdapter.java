package io.helixiam.authorization.amqp.gdpr.adapter;

import com.fasterxml.jackson.core.type.TypeReference;
import io.helixiam.authorization.amqp.gdpr.GdprConsentRecordDto;
import io.helixiam.authorization.amqp.gdpr.GdprConsentWithdrawDto;
import io.helixiam.authorization.amqp.gdpr.GdprConsentWriteDto;
import io.helixiam.authorization.amqp.gdpr.GdprEraseDto;
import io.helixiam.authorization.amqp.gdpr.GdprEraseResultDto;
import io.helixiam.authorization.amqp.gdpr.GdprExportDto;
import io.helixiam.authorization.amqp.gdpr.GdprPublisher;
import io.helixiam.authorization.amqp.gdpr.GdprUserRef;
import io.helixiam.authorization.amqp.support.DtoBridge;
import io.helixiam.authorization.service.gdpr.ConsentLedgerService;
import io.helixiam.authorization.service.gdpr.GdprAdminService;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * Strip-RabbitMQ (Task 3): in-process adapter replacing the former AMQP transport of
 * {@link GdprPublisher}.
 */
@Component
public class GdprLocalAdapter implements GdprPublisher {

    private final GdprAdminService gdpr;
    private final ConsentLedgerService consents;
    private final DtoBridge bridge;

    public GdprLocalAdapter(final GdprAdminService gdpr, final ConsentLedgerService consents, final DtoBridge bridge) {
        this.gdpr = gdpr;
        this.consents = consents;
        this.bridge = bridge;
    }

    @Override
    public GdprExportDto export(final GdprUserRef ref) {
        return bridge.to(gdpr.export(ref.realmId(), ref.userId()), GdprExportDto.class);
    }

    @Override
    public GdprEraseResultDto erase(final GdprEraseDto erase) {
        return bridge.to(gdpr.erase(
                bridge.to(erase, io.helixiam.authorization.domain.gdpr.GdprEraseDto.class)),
                GdprEraseResultDto.class);
    }

    @Override
    public List<GdprConsentRecordDto> listConsents(final GdprUserRef ref) {
        return bridge.to(consents.list(ref.realmId(), ref.userId()),
                new TypeReference<List<GdprConsentRecordDto>>() { });
    }

    @Override
    public GdprConsentRecordDto recordConsent(final GdprConsentWriteDto write) {
        return bridge.to(consents.record(
                bridge.to(write, io.helixiam.authorization.domain.gdpr.GdprConsentWriteDto.class)),
                GdprConsentRecordDto.class);
    }

    @Override
    public Boolean withdrawConsent(final GdprConsentWithdrawDto withdraw) {
        return consents.withdraw(
                bridge.to(withdraw, io.helixiam.authorization.domain.gdpr.GdprConsentWithdrawDto.class));
    }
}
