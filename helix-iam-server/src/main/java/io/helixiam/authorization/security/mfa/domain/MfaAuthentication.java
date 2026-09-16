/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.security.mfa.domain;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.CredentialsContainer;

import java.util.List;

public class MfaAuthentication extends AbstractAuthenticationToken {

    private final Authentication original;

    public MfaAuthentication(final Authentication original) {
        super(List.of());
        this.original = original;
    }

    @Override
    public Object getCredentials() {
        return original.getCredentials();
    }

    @Override
    public Object getPrincipal() {
        return original.getPrincipal();
    }

    @Override
    public void eraseCredentials() {
        if (this.original instanceof CredentialsContainer credentialsContainer) {
            credentialsContainer.eraseCredentials();
        }
    }

    @Override
    public boolean isAuthenticated() {
        return false;
    }

    public Authentication getOriginalUserObject() {
        return original;
    }
}
