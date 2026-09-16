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

    public void unlockUser() {
        final Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if(authentication instanceof MfaAuthentication mfaAuthentication) {
            SecurityContextHolder.getContext().setAuthentication(mfaAuthentication.getOriginalUserObject());
        }
    }
}
