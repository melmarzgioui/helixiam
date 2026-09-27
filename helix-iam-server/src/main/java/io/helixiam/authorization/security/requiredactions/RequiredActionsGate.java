/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.security.requiredactions;

import io.helixiam.authorization.amqp.user.UserAdminPublisher;
import io.helixiam.authorization.domain.UserCredentials;
import io.helixiam.authorization.security.mfa.domain.MfaAuthentication;
import io.helixiam.authorization.security.realm.RealmContextHolder;
import io.helixiam.authorization.service.emailverification.EmailVerificationService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import io.helixiam.common.log.LogSafe;
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
    private final EmailVerificationService emailVerification;
    private final HttpSessionSecurityContextRepository contextRepository = new HttpSessionSecurityContextRepository();

    public RequiredActionsGate(final UserAdminPublisher userPublisher, final EmailVerificationService emailVerification) {
        this.userPublisher = userPublisher;
        this.emailVerification = emailVerification;
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
        final String stored;
        try {
            stored = userPublisher.getRequiredActions(user.getUserId());
        } catch (final RuntimeException e) {
            LOG.debug("Required-actions lookup failed for {}, continuing login: {}", user.getUserId(), e.getMessage());
            return false;
        }
        // C3: VERIFY_EMAIL is enforced, not acknowledged — it is pending exactly while the address is unverified and
        // either the realm requires verification or an admin set the action. Never swallowed: a lookup failure here
        // must not let an unverified user through (the token guard would refuse the tokens anyway).
        final String pending = withEmailVerification(stored, emailVerification.pending(RealmContextHolder.get(),
                user.getUserId()));
        if (EmailVerificationService.hasAction(stored) && !EmailVerificationService.hasAction(pending)) {
            emailVerification.clearIfVerified(user.getUserId());
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
        LOG.info("User {} held for required actions [{}]", LogSafe.sanitize(user.getUserId()), LogSafe.sanitize(pending));
        response.sendRedirect(request.getContextPath() + "/required-actions");
        return true;
    }

    /** The stored actions with {@code VERIFY_EMAIL} first when {@code verify} is set, and without it otherwise. */
    static String withEmailVerification(final String stored, final boolean verify) {
        final java.util.List<String> actions = new java.util.ArrayList<>();
        if (verify) {
            actions.add(EmailVerificationService.VERIFY_EMAIL);
        }
        if (stored != null) {
            java.util.Arrays.stream(stored.split(",")).map(String::trim).filter(a -> !a.isEmpty())
                    .filter(a -> !EmailVerificationService.VERIFY_EMAIL.equalsIgnoreCase(a)).forEach(actions::add);
        }
        return String.join(",", actions);
    }
}
