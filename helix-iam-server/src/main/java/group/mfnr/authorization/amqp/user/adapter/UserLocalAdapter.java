package group.mfnr.authorization.amqp.user.adapter;

import group.mfnr.authorization.amqp.support.DtoBridge;
import group.mfnr.authorization.amqp.user.UserPublisher;
import group.mfnr.authorization.domain.ChangePassword;
import group.mfnr.authorization.domain.UserRegister;
import group.mfnr.authorization.service.UserService;
import org.springframework.stereotype.Component;

import java.util.Map;
import java.util.Set;

/**
 * Strip-RabbitMQ (Task 3): in-process adapter replacing the former AMQP transport of
 * {@link UserPublisher}.
 *
 * <p>DEVIATION: the former listeners for {@code selfSignup} / {@code resetPasswordUpdate} called
 * {@code group.mfnr.subscriber.starter.validation.Validator.validate(...)} (a bean-validation guard from
 * the deleted AMQP starter, not vendored). It is omitted here — these endpoints are already validated at
 * the controller layer. See ADAPTERS.md "deviations".
 */
@Component
public class UserLocalAdapter implements UserPublisher {

    private final UserService userService;
    private final DtoBridge bridge;

    public UserLocalAdapter(final UserService userService, final DtoBridge bridge) {
        this.userService = userService;
        this.bridge = bridge;
    }

    @Override
    public Map<String, String> getClaimProfile(final String userId) {
        return userService.userClaims(userId);
    }

    @Override
    public UserRegister selfSignup(final UserRegister userRegister) {
        final group.mfnr.authorization.domain.user.UserCredentials uc =
                bridge.to(userRegister, group.mfnr.authorization.domain.user.UserCredentials.class);
        return bridge.to(userService.save(uc, uc.getUsername()), UserRegister.class);
    }

    @Override
    public Boolean resetPasswordRequest(final String userName) {
        return userService.resetPasswordRequest(userName) != null;
    }

    @Override
    public Boolean resetPasswordUpdate(final ChangePassword changePassword) {
        return userService.resetPasswordUpdate(
                bridge.to(changePassword, group.mfnr.authorization.domain.user.ChangePassword.class));
    }

    @Override
    public Boolean verifyEmail(final String code) {
        return userService.verifyEmail(code);
    }

    @Override
    public Boolean enableMfa(final String userId) {
        userService.enableMfa(userId);
        return Boolean.TRUE;
    }

    @Override
    public Set<String> getUserInRoles(final String userId) {
        return userService.getUserInRoles(userId);
    }
}
