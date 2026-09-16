package group.mfnr.authorization.amqp;

import group.mfnr.authorization.domain.LoginCredentials;
import group.mfnr.authorization.domain.UserCredentials;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

public interface LoginPublisher {
    String EXCHANGE_AUTHORIZATION_LOGIN = "exchange-authorization-login";
    String AUTHORIZATION_LOGIN_LOGIN = "authorization.login.login";

    UserCredentials login(final LoginCredentials loginCredentials) throws UsernameNotFoundException;
}
