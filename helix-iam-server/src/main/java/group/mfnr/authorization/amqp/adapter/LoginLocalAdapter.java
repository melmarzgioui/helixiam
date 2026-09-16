package group.mfnr.authorization.amqp.adapter;

import group.mfnr.authorization.amqp.LoginPublisher;
import group.mfnr.authorization.amqp.support.DtoBridge;
import group.mfnr.authorization.domain.LoginCredentials;
import group.mfnr.authorization.domain.UserCredentials;
import group.mfnr.authorization.service.LoginService;
import org.springframework.stereotype.Component;

/**
 * Strip-RabbitMQ (Task 3): in-process adapter replacing the former AMQP transport of
 * {@link LoginPublisher}. The domain {@code group.mfnr.authorization.domain.user.UserCredentials} returned
 * by the service is bridged to the web front's {@link UserCredentials} view (the login exchange's two-copy
 * DTO).
 */
@Component
public class LoginLocalAdapter implements LoginPublisher {

    private final LoginService loginService;
    private final DtoBridge bridge;

    public LoginLocalAdapter(final LoginService loginService, final DtoBridge bridge) {
        this.loginService = loginService;
        this.bridge = bridge;
    }

    @Override
    public UserCredentials login(final LoginCredentials loginCredentials) {
        return bridge.to(loginService.loginUser(loginCredentials), UserCredentials.class);
    }
}
