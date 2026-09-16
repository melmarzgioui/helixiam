package group.mfnr.authorization.amqp.flow.adapter;

import com.fasterxml.jackson.core.type.TypeReference;
import group.mfnr.authorization.amqp.flow.FlowAdminPublisher;
import group.mfnr.authorization.amqp.flow.FlowCreateDto;
import group.mfnr.authorization.amqp.flow.FlowDefinitionDto;
import group.mfnr.authorization.amqp.flow.FlowRefDto;
import group.mfnr.authorization.amqp.flow.FlowRenameDto;
import group.mfnr.authorization.amqp.flow.FlowSaveDto;
import group.mfnr.authorization.amqp.flow.FlowSummaryDto;
import group.mfnr.authorization.amqp.support.DtoBridge;
import group.mfnr.authorization.service.flow.FlowAdminService;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * Strip-RabbitMQ (Task 3): in-process adapter replacing the former AMQP transport of
 * {@link FlowAdminPublisher}. {@code get} resolves the realm's fixed {@code browser} flow (as the former
 * listener did).
 */
@Component
public class FlowAdminLocalAdapter implements FlowAdminPublisher {

    private static final String BROWSER_ALIAS = "browser";

    private final FlowAdminService service;
    private final DtoBridge bridge;

    public FlowAdminLocalAdapter(final FlowAdminService service, final DtoBridge bridge) {
        this.service = service;
        this.bridge = bridge;
    }

    @Override
    public FlowDefinitionDto get(final String realmId) {
        return bridge.to(service.get(realmId, BROWSER_ALIAS), FlowDefinitionDto.class);
    }

    @Override
    public FlowDefinitionDto save(final FlowSaveDto dto) {
        return bridge.to(service.save(
                bridge.to(dto, group.mfnr.authorization.domain.flow.admin.FlowSaveDto.class)),
                FlowDefinitionDto.class);
    }

    @Override
    public List<FlowSummaryDto> list(final String realmId) {
        return bridge.to(service.list(realmId), new TypeReference<List<FlowSummaryDto>>() { });
    }

    @Override
    public FlowDefinitionDto getByAlias(final FlowRefDto ref) {
        return bridge.to(service.get(ref.realmId(), ref.alias()), FlowDefinitionDto.class);
    }

    @Override
    public FlowSummaryDto create(final FlowCreateDto dto) {
        return bridge.to(service.create(dto.realmId(), dto.alias(), dto.copyFromAlias()), FlowSummaryDto.class);
    }

    @Override
    public FlowSummaryDto rename(final FlowRenameDto dto) {
        return bridge.to(service.rename(dto.realmId(), dto.alias(), dto.newAlias()), FlowSummaryDto.class);
    }

    @Override
    public void delete(final FlowRefDto ref) {
        service.delete(ref.realmId(), ref.alias());
    }
}
