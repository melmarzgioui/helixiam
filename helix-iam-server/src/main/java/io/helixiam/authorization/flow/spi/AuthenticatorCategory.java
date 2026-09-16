/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.flow.spi;

/**
 * Helix IAM: how the admin console's flow editor should present an authenticator. This is a
 * <em>backend-declared</em> classification so the console never has to guess from
 * {@link FactorClass}/level-of-assurance heuristics.
 */
public enum AuthenticatorCategory {
    /** A sign-in step the user actually performs (password, OTP, passkey, IdP redirect, consent). */
    METHOD,
    /** A predicate that gates a sub-flow (e.g. adaptive risk) — never a step the user "does". */
    CONDITION
}
