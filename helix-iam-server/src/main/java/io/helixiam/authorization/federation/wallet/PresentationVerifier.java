/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.wallet;

/**
 * Verifies one credential format. Implementations throw {@link WalletVerificationException} on any failure; they
 * never return a partially verified result.
 */
public interface PresentationVerifier {
    String format();
    VerifiedPresentation verify(String rawPresentation, VerificationContext context);
}
