package group.mfnr.authorization.amqp.user.adapter;

import com.fasterxml.jackson.core.type.TypeReference;
import group.mfnr.authorization.amqp.support.DtoBridge;
import group.mfnr.authorization.amqp.user.CredentialRevokeRef;
import group.mfnr.authorization.amqp.user.CredentialSummary;
import group.mfnr.authorization.amqp.user.UserAdminDto;
import group.mfnr.authorization.amqp.user.UserAdminPublisher;
import group.mfnr.authorization.amqp.user.UserAdminRef;
import group.mfnr.authorization.amqp.user.UserChangePasswordDto;
import group.mfnr.authorization.amqp.user.UserPasswordDto;
import group.mfnr.authorization.amqp.user.UserRequiredActionsDto;
import group.mfnr.authorization.amqp.user.UserWriteDto;
import group.mfnr.authorization.service.user.CredentialAdminService;
import group.mfnr.authorization.service.user.UserAdminService;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * Strip-RabbitMQ (Task 3): in-process adapter replacing the former AMQP transport of
 * {@link UserAdminPublisher}.
 */
@Component
public class UserAdminLocalAdapter implements UserAdminPublisher {


    private final UserAdminService service;
    private final CredentialAdminService credentials;
    private final DtoBridge bridge;

    public UserAdminLocalAdapter(final UserAdminService service, final CredentialAdminService credentials,
                                 final DtoBridge bridge) {
        this.service = service;
        this.credentials = credentials;
        this.bridge = bridge;
    }

    @Override
    public List<UserAdminDto> list(final String realmId) {
        return bridge.to(service.list(realmId), new TypeReference<List<UserAdminDto>>() { });
    }

    @Override
    public UserAdminDto get(final UserAdminRef ref) {
        return bridge.to(service.get(ref.realmId(), ref.userId()).orElse(null), UserAdminDto.class);
    }

    @Override
    public UserAdminDto create(final UserWriteDto write) {
        return bridge.to(service.create(
                bridge.to(write, group.mfnr.authorization.domain.user.admin.UserWriteDto.class)), UserAdminDto.class);
    }

    @Override
    public UserAdminDto update(final UserWriteDto write) {
        return bridge.to(service.update(
                bridge.to(write, group.mfnr.authorization.domain.user.admin.UserWriteDto.class)).orElse(null),
                UserAdminDto.class);
    }

    @Override
    public Boolean resetPassword(final UserPasswordDto reset) {
        return service.resetPassword(
                bridge.to(reset, group.mfnr.authorization.domain.user.admin.UserPasswordDto.class));
    }

    @Override
    public Boolean changePassword(final UserChangePasswordDto change) {
        return service.changePassword(
                bridge.to(change, group.mfnr.authorization.domain.user.admin.UserChangePasswordDto.class));
    }

    @Override
    public Boolean delete(final UserAdminRef ref) {
        return service.delete(ref.realmId(), ref.userId());
    }

    @Override
    public List<CredentialSummary> listCredentials(final UserAdminRef ref) {
        return bridge.to(credentials.list(ref.userId()), new TypeReference<List<CredentialSummary>>() { });
    }

    @Override
    public Boolean revokeCredential(final CredentialRevokeRef ref) {
        return credentials.revoke(ref.userId(), ref.type(), ref.id());
    }

    @Override
    public Boolean setRequiredActions(final UserRequiredActionsDto dto) {
        return service.setRequiredActions(dto.userId(), dto.requiredActions());
    }

    @Override
    public String getRequiredActions(final String userId) {
        return service.getRequiredActions(userId);
    }

    @Override
    public String clearRequiredAction(final UserRequiredActionsDto dto) {
        return service.clearRequiredAction(dto.userId(), dto.requiredActions());
    }
}
