package io.helixiam.authorization.amqp;

import io.helixiam.authorization.domain.LoginCredentials;
import io.helixiam.authorization.domain.UserCredentials;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

public interface LoginPublisher {
    String EXCHANGE_AUTHORIZATION_LOGIN = "exchange-authorization-login";
    String AUTHORIZATION_LOGIN_LOGIN = "authorization.login.login";

    UserCredentials login(final LoginCredentials loginCredentials) throws UsernameNotFoundException;
}
