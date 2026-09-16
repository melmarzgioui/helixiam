/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.flow.authenticators;

import io.helixiam.authorization.flow.spi.AuthenticationContext;
import io.helixiam.authorization.flow.spi.Authenticator;
import io.helixiam.authorization.flow.spi.AuthenticatorMetadata;
import io.helixiam.authorization.flow.spi.FactorClass;

import java.security.SecureRandom;
import java.util.Base64;

/**
 * Helix IAM E4.1: the VeridPay-style device factor. {@link #authenticate} issues a single-use
 * server challenge (held for replay protection) and renders the device-approval view; the enrolled
 * phone signs the exact challenge bytes with its Secure-Enclave/StrongBox key. {@link #action} packs
 * the assertion (deviceId + challenge + ES256 signature) and verifies it via the generic
 * {@link CredentialVerifier} under credential type {@code "device"} (the subscriber's provider checks
 * the signature against the enrolled public key). Cross-device QR delivery + push land in E4.2/E4.3.
 */
public class DeviceAuthenticator implements Authenticator {

    static final String VIEW = "device-form";
    static final String CHALLENGE_ATTRIBUTE = "device.challenge";
    static final String CREDENTIAL_TYPE = "device";

    private static final SecureRandom RANDOM = new SecureRandom();

    private final CredentialVerifier verifier;

    public DeviceAuthenticator(final CredentialVerifier verifier) {
        this.verifier = verifier;
    }

    @Override
    public AuthenticatorMetadata metadata() {
        return AuthenticatorMetadata.of("device", "Trusted Device", FactorClass.POSSESSION, 4);
    }

    @Override
    public void authenticate(final AuthenticationContext context) {
        final byte[] challenge = new byte[32];
        RANDOM.nextBytes(challenge);
        context.putAttribute(CHALLENGE_ATTRIBUTE, Base64.getUrlEncoder().withoutPadding().encodeToString(challenge));
        context.challenge(VIEW);
    }

    @Override
    public void action(final AuthenticationContext context) {
        final Object challenge = context.getAttribute(CHALLENGE_ATTRIBUTE);
        final String deviceId = context.formParameter("deviceId");
        final String signature = context.formParameter("signature");
        if (challenge == null || deviceId == null || signature == null) {
            context.failure("Missing device assertion");
            return;
        }
        final String input = json(
                "deviceId", deviceId,
                "challenge", challenge.toString(),
                "signature", signature);
        if (verifier.verify(CREDENTIAL_TYPE, context.userId(), input)) {
            context.success();
        } else {
            context.failure("Device verification failed");
        }
    }

    /** Minimal JSON object builder (string keys/values, JSON-escaped). */
    private static String json(final String... kv) {
        final StringBuilder sb = new StringBuilder("{");
        for (int i = 0; i < kv.length; i += 2) {
            if (i > 0) {
                sb.append(',');
            }
            sb.append('"').append(kv[i]).append("\":\"").append(escape(kv[i + 1])).append('"');
        }
        return sb.append('}').toString();
    }

    private static String escape(final String value) {
        return value.replace("\\", "\\\\").replace("\"", "\\\"");
    }
}
