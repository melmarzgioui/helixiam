/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.security.mfa;

import io.helixiam.authorization.domain.UserCredentials;

public interface MfaAuthenticationCodeVerifier {
    boolean verify(final UserCredentials userCredentials, final String code);
}
