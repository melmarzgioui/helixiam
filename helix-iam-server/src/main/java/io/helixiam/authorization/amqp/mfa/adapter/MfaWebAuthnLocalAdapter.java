/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.amqp.mfa.adapter;

import io.helixiam.authorization.amqp.mfa.MfaWebAuthnPublisher;
import io.helixiam.authorization.amqp.mfa.WebAuthnRegistration;
import io.helixiam.authorization.amqp.mfa.WebAuthnResidentAssertion;
import io.helixiam.authorization.service.mfa.WebAuthnService;
import org.springframework.stereotype.Component;

import java.util.Base64;

/**
 * Strip-RabbitMQ (Task 3): in-process adapter replacing the former AMQP transport of
 * {@link MfaWebAuthnPublisher}. Reproduces the former listener's Base64URL decoding of the wire fields.
 */
@Component
public class MfaWebAuthnLocalAdapter implements MfaWebAuthnPublisher {

    private final WebAuthnService webAuthnService;

    public MfaWebAuthnLocalAdapter(final WebAuthnService webAuthnService) {
        this.webAuthnService = webAuthnService;
    }

    @Override
    public Boolean register(final WebAuthnRegistration registration) {
        return webAuthnService.finishRegistration(
                registration.getUserId(),
                Base64.getUrlDecoder().decode(registration.getAttestationObject()),
                Base64.getUrlDecoder().decode(registration.getClientDataJSON()),
                registration.getChallenge(),
                registration.getOrigin(),
                registration.getRpId());
    }

    @Override
    public String loginResident(final WebAuthnResidentAssertion assertion) {
        return webAuthnService.resolveAndVerifyAssertion(
                urlDecode(assertion.getCredentialId()),
                urlDecode(assertion.getUserHandle()),
                urlDecode(assertion.getAuthenticatorData()),
                urlDecode(assertion.getClientDataJSON()),
                urlDecode(assertion.getSignature()),
                assertion.getChallenge(),
                assertion.getOrigin(),
                assertion.getRpId());
    }

    private static byte[] urlDecode(final String value) {
        return value == null || value.isEmpty() ? new byte[0] : Base64.getUrlDecoder().decode(value);
    }
}
