package io.helixiam.authorization.federation;

import io.helixiam.authorization.amqp.federation.FederatedIdentityPublisher;
import io.helixiam.authorization.domain.UserCredentials;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.stereotype.Component;

/**
 * Helix IAM E5.3/E5.4: the primitives that establish the local login session after a successful
 * external (federated) login — {@link #loadUser(String)} fetches the broker-resolved user
 * passwordlessly over AMQP, and {@link #persist(Authentication, HttpServletRequest, HttpServletResponse)}
 * installs a given {@link Authentication} into a fresh SecurityContext saved to the HTTP session.
 * {@link FederatedLoginCompleter} composes these with the post-broker flow (which may hold a
 * non-authenticated {@code MfaAuthentication} gate for step-up before completing).
 *
 * <p>This is the security-sensitive seam: {@code loadUser} trusts the {@code userId} as already
 * authenticated, so it is only called after the provider's {@code callback} cryptographically
 * validated the IdP response (or an existing verified link matched).
 */
@Component
public class FederatedSessionEstablisher {

    private static final Logger LOG = LogManager.getLogger(FederatedSessionEstablisher.class);

    private final FederatedIdentityPublisher publisher;
    private final SecurityContextRepository securityContextRepository;

    @Autowired
    public FederatedSessionEstablisher(final FederatedIdentityPublisher publisher) {
        this(publisher, new HttpSessionSecurityContextRepository());
    }

    FederatedSessionEstablisher(final FederatedIdentityPublisher publisher,
                                final SecurityContextRepository securityContextRepository) {
        this.publisher = publisher;
        this.securityContextRepository = securityContextRepository;
    }

    /** Passwordlessly load the broker-resolved user; hard failure if it cannot be loaded. */
    public UserCredentials loadUser(final String userId) {
        final UserCredentials user = publisher.loadUser(userId);
        if (user == null) {
            throw new IllegalStateException("Federated login resolved user " + userId + " but it could not be loaded");
        }
        return user;
    }

    /** Install the given authentication into a fresh SecurityContext and persist it to the session. */
    public void persist(final Authentication authentication, final HttpServletRequest request,
                        final HttpServletResponse response) {
        final SecurityContext context = SecurityContextHolder.createEmptyContext();
        context.setAuthentication(authentication);
        SecurityContextHolder.setContext(context);
        securityContextRepository.saveContext(context, request, response);
        LOG.debug("Persisted federated SecurityContext (authenticated={})", authentication.isAuthenticated());
    }
}
