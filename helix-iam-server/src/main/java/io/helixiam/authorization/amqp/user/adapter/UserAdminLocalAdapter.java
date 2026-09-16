package io.helixiam.authorization.amqp.user.adapter;

import com.fasterxml.jackson.core.type.TypeReference;
import io.helixiam.authorization.amqp.support.DtoBridge;
import io.helixiam.authorization.amqp.user.CredentialRevokeRef;
import io.helixiam.authorization.amqp.user.CredentialSummary;
import io.helixiam.authorization.amqp.user.UserAdminDto;
import io.helixiam.authorization.amqp.user.UserAdminPublisher;
import io.helixiam.authorization.amqp.user.UserAdminRef;
import io.helixiam.authorization.amqp.user.UserChangePasswordDto;
import io.helixiam.authorization.amqp.user.UserPasswordDto;
import io.helixiam.authorization.amqp.user.UserRequiredActionsDto;
import io.helixiam.authorization.amqp.user.UserWriteDto;
import io.helixiam.authorization.service.user.CredentialAdminService;
import io.helixiam.authorization.service.user.UserAdminService;
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
                bridge.to(write, io.helixiam.authorization.domain.user.admin.UserWriteDto.class)), UserAdminDto.class);
    }

    @Override
    public UserAdminDto update(final UserWriteDto write) {
        return bridge.to(service.update(
                bridge.to(write, io.helixiam.authorization.domain.user.admin.UserWriteDto.class)).orElse(null),
                UserAdminDto.class);
    }

    @Override
    public Boolean resetPassword(final UserPasswordDto reset) {
        return service.resetPassword(
                bridge.to(reset, io.helixiam.authorization.domain.user.admin.UserPasswordDto.class));
    }

    @Override
    public Boolean changePassword(final UserChangePasswordDto change) {
        return service.changePassword(
                bridge.to(change, io.helixiam.authorization.domain.user.admin.UserChangePasswordDto.class));
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
