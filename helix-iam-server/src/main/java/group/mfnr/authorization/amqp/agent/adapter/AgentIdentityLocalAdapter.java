package group.mfnr.authorization.amqp.agent.adapter;

import com.fasterxml.jackson.core.type.TypeReference;
import group.mfnr.authorization.amqp.agent.AgentClientQuery;
import group.mfnr.authorization.amqp.agent.AgentIdentityDto;
import group.mfnr.authorization.amqp.agent.AgentIdentityPublisher;
import group.mfnr.authorization.amqp.agent.AgentIdentityRef;
import group.mfnr.authorization.amqp.agent.AgentOwnerReviewDto;
import group.mfnr.authorization.amqp.support.DtoBridge;
import group.mfnr.authorization.service.agent.AgentIdentityAdminService;
import group.mfnr.authorization.service.agent.AgentOwnerReviewService;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * Strip-RabbitMQ (Task 3): in-process adapter replacing the former AMQP transport of
 * {@link AgentIdentityPublisher}.
 */
@Component
public class AgentIdentityLocalAdapter implements AgentIdentityPublisher {

    private final AgentIdentityAdminService service;
    private final AgentOwnerReviewService ownerReview;
    private final DtoBridge bridge;

    public AgentIdentityLocalAdapter(final AgentIdentityAdminService service,
                                     final AgentOwnerReviewService ownerReview,
                                     final DtoBridge bridge) {
        this.service = service;
        this.ownerReview = ownerReview;
        this.bridge = bridge;
    }

    @Override
    public List<AgentIdentityDto> list(final String realmId) {
        return bridge.to(service.list(realmId), new TypeReference<List<AgentIdentityDto>>() { });
    }

    @Override
    public List<AgentOwnerReviewDto> ownerReview(final String realmId) {
        return bridge.to(ownerReview.review(realmId), new TypeReference<List<AgentOwnerReviewDto>>() { });
    }

    @Override
    public AgentIdentityDto get(final AgentIdentityRef ref) {
        return bridge.to(service.get(ref.realmId(), ref.id()), AgentIdentityDto.class);
    }

    @Override
    public AgentIdentityDto save(final AgentIdentityDto dto) {
        return bridge.to(service.save(
                bridge.to(dto, group.mfnr.authorization.domain.agent.AgentIdentityDto.class)),
                AgentIdentityDto.class);
    }

    @Override
    public Boolean delete(final AgentIdentityRef ref) {
        return service.delete(ref.realmId(), ref.id());
    }

    @Override
    public AgentIdentityDto suspend(final AgentIdentityRef ref) {
        return bridge.to(service.suspend(ref.realmId(), ref.id()), AgentIdentityDto.class);
    }

    @Override
    public AgentIdentityDto activate(final AgentIdentityRef ref) {
        return bridge.to(service.activate(ref.realmId(), ref.id()), AgentIdentityDto.class);
    }

    @Override
    public AgentIdentityDto revoke(final AgentIdentityRef ref) {
        return bridge.to(service.revoke(ref.realmId(), ref.id()), AgentIdentityDto.class);
    }

    @Override
    public AgentIdentityDto findByClient(final AgentClientQuery query) {
        return bridge.to(service.findByClientId(query.realmId(), query.clientId()), AgentIdentityDto.class);
    }
}
