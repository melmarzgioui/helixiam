/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.security.requiredactions;

import io.helixiam.authorization.amqp.user.UserAdminPublisher;
import io.helixiam.authorization.domain.UserCredentials;
import io.helixiam.authorization.security.mfa.domain.MfaAuthentication;
import io.helixiam.authorization.security.realm.RealmContextHolder;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.stereotype.Component;

import java.io.IOException;

/**
 * Helix IAM B1: the post-password gate that holds a user pending their required actions. If the
 * just-authenticated user has any required actions, this stashes the (real) Authentication + the pending
 * list on the session, demotes the security context to a partial {@link MfaAuthentication} (not yet
 * authenticated — same model as the MFA step-up gate) and redirects to {@code /required-actions}. The
 * {@code RequiredActionsController} completes each action and then hands the original Authentication back
 * to the normal post-password routing so MFA/flow still runs.
 */
@Component
public class RequiredActionsGate {

    public static final String PENDING_AUTH_ATTR = "HELIX_REQUIRED_ACTIONS_AUTH";
    public static final String PENDING_ACTIONS_ATTR = "HELIX_REQUIRED_ACTIONS_PENDING";
    public static final String PENDING_REALM_ATTR = "HELIX_REQUIRED_ACTIONS_REALM";

    private static final Logger LOG = LogManager.getLogger(RequiredActionsGate.class);

    private final UserAdminPublisher userPublisher;
    private final HttpSessionSecurityContextRepository contextRepository = new HttpSessionSecurityContextRepository();

    public RequiredActionsGate(final UserAdminPublisher userPublisher) {
        this.userPublisher = userPublisher;
    }

    /**
     * @return {@code true} if the user has pending required actions and the request was redirected to the
     *         completion flow (the caller must stop processing); {@code false} to continue the normal login.
     */
    public boolean intercept(final HttpServletRequest request, final HttpServletResponse response,
                             final Authentication authentication) throws IOException {
        if (!(authentication.getPrincipal() instanceof UserCredentials user)) {
            return false;
        }
        final String pending;
        try {
            pending = userPublisher.getRequiredActions(user.getUserId());
        } catch (final RuntimeException e) {
            LOG.debug("Required-actions lookup failed for {}, continuing login: {}", user.getUserId(), e.getMessage());
            return false;
        }
        if (pending == null || pending.isBlank()) {
            return false;
        }
        final HttpSession session = request.getSession();
        session.setAttribute(PENDING_AUTH_ATTR, authentication);
        session.setAttribute(PENDING_ACTIONS_ATTR, pending);
        session.setAttribute(PENDING_REALM_ATTR, RealmContextHolder.get());
        // Demote to a partial (not-authenticated) context so the user can only reach /required-actions.
        SecurityContextHolder.getContext().setAuthentication(new MfaAuthentication(authentication));
        contextRepository.saveContext(SecurityContextHolder.getContext(), request, response);
        LOG.info("User {} held for required actions [{}]", user.getUserId(), pending);
        response.sendRedirect(request.getContextPath() + "/required-actions");
        return true;
    }
}
