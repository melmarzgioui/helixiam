package group.mfnr.authorization.amqp.org.adapter;

import com.fasterxml.jackson.core.type.TypeReference;
import group.mfnr.authorization.amqp.org.OrgDto;
import group.mfnr.authorization.amqp.org.OrgMemberDto;
import group.mfnr.authorization.amqp.org.OrgMembershipDto;
import group.mfnr.authorization.amqp.org.OrgRef;
import group.mfnr.authorization.amqp.org.OrgWriteDto;
import group.mfnr.authorization.amqp.org.OrganizationAdminPublisher;
import group.mfnr.authorization.amqp.support.DtoBridge;
import group.mfnr.authorization.service.org.OrganizationAdminService;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * Strip-RabbitMQ (Task 3): in-process adapter replacing the former AMQP transport of
 * {@link OrganizationAdminPublisher}.
 */
@Component
public class OrganizationAdminLocalAdapter implements OrganizationAdminPublisher {

    private final OrganizationAdminService service;
    private final DtoBridge bridge;

    public OrganizationAdminLocalAdapter(final OrganizationAdminService service, final DtoBridge bridge) {
        this.service = service;
        this.bridge = bridge;
    }

    private group.mfnr.authorization.domain.org.admin.OrgRef ref(final OrgRef ref) {
        return bridge.to(ref, group.mfnr.authorization.domain.org.admin.OrgRef.class);
    }

    @Override
    public List<OrgDto> list(final String realmId) {
        return bridge.to(service.list(realmId), new TypeReference<List<OrgDto>>() { });
    }

    @Override
    public OrgDto get(final OrgRef ref) {
        return bridge.to(service.get(ref.realmId(), ref.orgId()).orElse(null), OrgDto.class);
    }

    @Override
    public OrgDto create(final OrgWriteDto write) {
        return bridge.to(service.create(
                bridge.to(write, group.mfnr.authorization.domain.org.admin.OrgWriteDto.class)), OrgDto.class);
    }

    @Override
    public OrgDto update(final OrgWriteDto write) {
        return bridge.to(service.update(
                bridge.to(write, group.mfnr.authorization.domain.org.admin.OrgWriteDto.class)), OrgDto.class);
    }

    @Override
    public Boolean delete(final OrgRef ref) {
        return service.delete(ref.realmId(), ref.orgId());
    }

    @Override
    public List<OrgMemberDto> members(final OrgRef ref) {
        return bridge.to(service.listMembers(ref(ref)), new TypeReference<List<OrgMemberDto>>() { });
    }

    @Override
    public Boolean addMember(final OrgRef ref) {
        return service.addMember(ref(ref));
    }

    @Override
    public Boolean removeMember(final OrgRef ref) {
        return service.removeMember(ref(ref));
    }

    @Override
    public List<OrgMembershipDto> memberships(final String userId) {
        return bridge.to(service.membershipsForUser(userId), new TypeReference<List<OrgMembershipDto>>() { });
    }
}
