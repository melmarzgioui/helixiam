/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.domain.mfa;

import java.io.Serializable;

/**
 * Helix IAM (10) Passwordless: a usernameless / resident-key login assertion (subscriber copy). Carries the
 * browser assertion (base64url) plus the server challenge; no userId — the owner is discovered from the
 * credential. All fields base64url-encoded as packed by the publisher.
 */
public class WebAuthnResidentAssertion implements Serializable {

    private static final long serialVersionUID = 1L;

    private String credentialId;
    private String userHandle;
    private String authenticatorData;
    private String clientDataJSON;
    private String signature;
    private String challenge;
    private String origin;
    private String rpId;

    public WebAuthnResidentAssertion() {
    }

    public String getCredentialId() {
        return credentialId;
    }

    public void setCredentialId(final String credentialId) {
        this.credentialId = credentialId;
    }

    public String getUserHandle() {
        return userHandle;
    }

    public void setUserHandle(final String userHandle) {
        this.userHandle = userHandle;
    }

    public String getAuthenticatorData() {
        return authenticatorData;
    }

    public void setAuthenticatorData(final String authenticatorData) {
        this.authenticatorData = authenticatorData;
    }

    public String getClientDataJSON() {
        return clientDataJSON;
    }

    public void setClientDataJSON(final String clientDataJSON) {
        this.clientDataJSON = clientDataJSON;
    }

    public String getSignature() {
        return signature;
    }

    public void setSignature(final String signature) {
        this.signature = signature;
    }

    public String getChallenge() {
        return challenge;
    }

    public void setChallenge(final String challenge) {
        this.challenge = challenge;
    }

    public String getOrigin() {
        return origin;
    }

    public void setOrigin(final String origin) {
        this.origin = origin;
    }

    public String getRpId() {
        return rpId;
    }

    public void setRpId(final String rpId) {
        this.rpId = rpId;
    }
}
