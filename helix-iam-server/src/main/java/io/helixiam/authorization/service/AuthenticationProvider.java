package io.helixiam.authorization.service;

import io.helixiam.authorization.amqp.LoginPublisher;
import io.helixiam.authorization.domain.LoginCredentials;
import io.helixiam.authorization.domain.UserCredentials;
import io.helixiam.authorization.federation.ldap.LdapLoginFallback;
import io.helixiam.authorization.security.realm.RealmContextHolder;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.dao.AbstractUserDetailsAuthenticationProvider;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class AuthenticationProvider extends AbstractUserDetailsAuthenticationProvider {
    private static final Logger LOG = LogManager.getLogger(AuthenticationProvider.class);
    private final LoginPublisher loginPublisher;
    private final LdapLoginFallback ldapLoginFallback;

    @Autowired
    private AuthenticationProvider(final LoginPublisher loginPublisher, final LdapLoginFallback ldapLoginFallback) {
        this.loginPublisher = loginPublisher;
        this.ldapLoginFallback = ldapLoginFallback;
    }

    @Override
    protected void additionalAuthenticationChecks(final UserDetails userDetails, final UsernamePasswordAuthenticationToken authentication) throws AuthenticationException {
        // swallow
    }

    @Override
    protected UserDetails retrieveUser(final String username, final UsernamePasswordAuthenticationToken authentication) throws AuthenticationException {
        return retrieveUser(username, authentication, false);
    }

    protected UserDetails retrieveUser(final String username, final UsernamePasswordAuthenticationToken authentication, final boolean retried) throws AuthenticationException {
        final UserCredentials responseObject = loginPublisher.login(new LoginCredentials(username, authentication.getCredentials().toString()));
        if(responseObject == null && !retried) {
            LOG.error("Subscriber not responding for '{}'", LoginPublisher.AUTHORIZATION_LOGIN_LOGIN);
            return retrieveUser(username, authentication, true);
        }

        if(responseObject == null) {
            // A3: no local user (or wrong local password) — try the realm's LDAP/AD federation providers.
            // A successful directory bind JIT-provisions/links a local user and returns it as the UserDetails.
            final Optional<UserCredentials> ldapUser =
                    ldapLoginFallback.authenticate(RealmContextHolder.get(), username, authentication.getCredentials().toString());
            if (ldapUser.isPresent()) {
                return ldapUser.get();
            }
            throw new BadCredentialsException(this.messages.getMessage("AbstractUserDetailsAuthenticationProvider.badCredentials", "Bad credentials"));
        }

        return responseObject;
    }
}
