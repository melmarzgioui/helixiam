/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.security.flow;

import io.helixiam.authorization.amqp.federation.FederatedIdentityPublisher;
import io.helixiam.authorization.domain.UserCredentials;
import io.helixiam.authorization.flow.spi.AuthenticationContext;
import io.helixiam.authorization.flow.spi.Authenticator;
import io.helixiam.authorization.flow.spi.AuthenticatorMetadata;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

/**
 * Helix IAM E2.5: a flow condition that passes when the flow's user has MFA enabled. It gates a
 * CONDITIONAL step-up sub-flow, replacing the old in-code {@code if (mfaEnabled)} branch with a
 * data-driven condition the admin console can rewire.
 *
 * <p>It answers for the user the flow is for ({@link AuthenticationContext#userId()}, the flow state's user), not
 * for whoever is in the security context: after a brokered (OIDC / SAML / eID) login the flow starts before any
 * authentication is in the context, and "no principal" must not read as "MFA not enabled". The (MFA-pending)
 * principal is used when it is that same user; otherwise the user is loaded by id. A flow user that cannot be
 * loaded fails the flow rather than skip the second factor. Only a flow that has no user yet falls back to the
 * principal.
 */
@Component
public class MfaEnabledCondition implements Authenticator {

    public static final String ID = "mfa-enabled";

    /** Loads a user by id (the same passwordless lookup the broker uses to complete a federated login). */
    private final FederatedIdentityPublisher users;

    public MfaEnabledCondition(final FederatedIdentityPublisher users) {
        this.users = users;
    }

    @Override
    public AuthenticatorMetadata metadata() {
        return AuthenticatorMetadata.condition(ID, "User has MFA enabled");
    }

    @Override
    public void authenticate(final AuthenticationContext context) {
        final UserCredentials user = flowUser(context.userId());
        if (user != null && user.isMfaEnabled()) {
            context.success();
        } else {
            context.failure("MFA not enabled");
        }
    }

    private UserCredentials flowUser(final String userId) {
        final UserCredentials principal = principal();
        if (userId == null || principal != null && userId.equals(principal.getUserId())) {
            return principal;
        }
        final UserCredentials loaded = users.loadUser(userId);
        if (loaded == null) {
            throw new IllegalStateException("The login flow's user could not be loaded; refusing to skip the MFA step");
        }
        return loaded;
    }

    private static UserCredentials principal() {
        final Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        final Object principal = authentication == null ? null : authentication.getPrincipal();
        return principal instanceof UserCredentials userCredentials ? userCredentials : null;
    }
}
