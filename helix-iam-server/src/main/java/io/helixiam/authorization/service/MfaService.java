/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.service;

import io.helixiam.authorization.amqp.user.UserPublisher;
import io.helixiam.authorization.domain.UserCredentials;
import io.helixiam.authorization.security.mfa.domain.MfaAuthentication;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

@Service
public class MfaService {

    private final UserPublisher userPublisher;

    public MfaService(final UserPublisher userPublisher) {
        this.userPublisher = userPublisher;
    }

    public boolean enableMfa(final UserCredentials accountUserDetails) {
        if(userPublisher.enableMfa(accountUserDetails.getUsername())) {
            unlockUser();
            return true;
        }

        return false;
    }

    /**
     * Promotes the pending authentication only when it is a pending second-factor sign-in ({@link MfaAuthentication}) of
     * exactly {@code expectedUserId} (the user a login flow completed for). Returns false, promoting nothing, when there
     * is no pending sign-in (e.g. the session is already fully signed in as someone, after a magic link) or it is
     * another user's: a flow left over from user A must never complete into user B's session (final review M4).
     */
    public boolean unlockUser(final String expectedUserId) {
        final Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (expectedUserId == null || !(authentication instanceof MfaAuthentication mfaAuthentication)) {
            return false;
        }
        final Object principal = mfaAuthentication.getPrincipal();
        final String pendingUserId = principal instanceof UserCredentials user ? user.getUserId() : null;
        if (!expectedUserId.equals(pendingUserId)) {
            return false;
        }
        SecurityContextHolder.getContext().setAuthentication(mfaAuthentication.getOriginalUserObject());
        return true;
    }

    /**
     * Whether the pending second-factor sign-in ({@link MfaAuthentication}) in this context is exactly
     * {@code expectedUserId}'s, without promoting it. False for {@code null}, for no pending sign-in, or another user's.
     */
    public boolean isPendingSignInOf(final String expectedUserId) {
        final Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (expectedUserId == null || !(authentication instanceof MfaAuthentication mfaAuthentication)) {
            return false;
        }
        return mfaAuthentication.getPrincipal() instanceof UserCredentials user && expectedUserId.equals(user.getUserId());
    }

    public void unlockUser() {
        final Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if(authentication instanceof MfaAuthentication mfaAuthentication) {
            SecurityContextHolder.getContext().setAuthentication(mfaAuthentication.getOriginalUserObject());
        }
    }
}
