/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.flow.spi;

/**
 * Helix IAM E2.1: the authentication-factor class an authenticator belongs to. Used for
 * assurance reasoning (a multi-factor login must combine distinct classes) and for grouping
 * authenticators in the admin console.
 */
public enum FactorClass {
    /** Something you know — password, recovery code. */
    KNOWLEDGE,
    /** Something you have — TOTP, OTP, passkey, trusted device. */
    POSSESSION,
    /** Something you are — biometric/inherence. */
    INHERENCE,
    /** No factor of its own — conditions, identity-provider redirects. */
    NONE
}
