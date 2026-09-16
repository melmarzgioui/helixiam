package io.helixiam.authorization.security.mfa.manager;

import java.util.function.Supplier;

import io.helixiam.authorization.security.mfa.domain.MfaAuthentication;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;

public class MfaAuthorizationManager implements AuthorizationManager<RequestAuthorizationContext> {

    @Override
    public AuthorizationDecision check(final Supplier<Authentication> authentication, final RequestAuthorizationContext object) {
        return new AuthorizationDecision(authentication.get() instanceof MfaAuthentication || authentication.get() instanceof UsernamePasswordAuthenticationToken);
    }
}
