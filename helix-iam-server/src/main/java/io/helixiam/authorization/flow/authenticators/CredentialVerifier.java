/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.flow.authenticators;

/**
 * Helix IAM: generic seam to verify a login credential against the identity domain's pluggable
 * {@code CredentialProvider} for that type. One seam for every credential-backed authenticator
 * (HOTP, recovery-code, …); the live adapter routes over AMQP to the subscriber's registry.
 */
@FunctionalInterface
public interface CredentialVerifier {
    boolean verify(String type, String userId, String input);
}
