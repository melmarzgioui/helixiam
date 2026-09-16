package group.mfnr.authorization.amqp.workloadidentity.adapter;

import com.fasterxml.jackson.core.type.TypeReference;
import group.mfnr.authorization.amqp.support.DtoBridge;
import group.mfnr.authorization.amqp.workloadidentity.WorkloadIdentityConfigPublisher;
import group.mfnr.authorization.amqp.workloadidentity.WorkloadIdentityCredentialDto;
import group.mfnr.authorization.amqp.workloadidentity.WorkloadIdentityCredentialRef;
import group.mfnr.authorization.amqp.workloadidentity.WorkloadIdentityResolveQuery;
import group.mfnr.authorization.service.workloadidentity.WorkloadIdentityCredentialAdminService;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * Strip-RabbitMQ (Task 3): in-process adapter replacing the former AMQP transport of
 * {@link WorkloadIdentityConfigPublisher}.
 */
@Component
public class WorkloadIdentityConfigLocalAdapter implements WorkloadIdentityConfigPublisher {

    private final WorkloadIdentityCredentialAdminService service;
    private final DtoBridge bridge;

    public WorkloadIdentityConfigLocalAdapter(final WorkloadIdentityCredentialAdminService service,
                                              final DtoBridge bridge) {
        this.service = service;
        this.bridge = bridge;
    }

    @Override
    public List<WorkloadIdentityCredentialDto> list(final String realmId) {
        return bridge.to(service.list(realmId), new TypeReference<List<WorkloadIdentityCredentialDto>>() { });
    }

    @Override
    public WorkloadIdentityCredentialDto get(final WorkloadIdentityCredentialRef ref) {
        return bridge.to(service.get(ref.realmId(), ref.id()), WorkloadIdentityCredentialDto.class);
    }

    @Override
    public WorkloadIdentityCredentialDto save(final WorkloadIdentityCredentialDto dto) {
        return bridge.to(service.save(bridge.to(dto,
                group.mfnr.authorization.domain.workloadidentity.WorkloadIdentityCredentialDto.class)),
                WorkloadIdentityCredentialDto.class);
    }

    @Override
    public Boolean delete(final WorkloadIdentityCredentialRef ref) {
        return service.delete(ref.realmId(), ref.id());
    }

    @Override
    public WorkloadIdentityCredentialDto resolve(final WorkloadIdentityResolveQuery query) {
        return bridge.to(service.resolve(query.realmId(), query.issuer(), query.subject(), query.audience())
                .orElse(null), WorkloadIdentityCredentialDto.class);
    }
}
