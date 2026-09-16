package io.helixiam.authorization.amqp.adapter;

import io.helixiam.authorization.amqp.LoginPublisher;
import io.helixiam.authorization.amqp.support.DtoBridge;
import io.helixiam.authorization.domain.LoginCredentials;
import io.helixiam.authorization.domain.UserCredentials;
import io.helixiam.authorization.service.LoginService;
import org.springframework.stereotype.Component;

/**
 * Strip-RabbitMQ (Task 3): in-process adapter replacing the former AMQP transport of
 * {@link LoginPublisher}. The domain {@code io.helixiam.authorization.domain.user.UserCredentials} returned
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
