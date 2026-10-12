/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.security.mfa;

import io.helixiam.authorization.service.mfa.MfaPolicyService;
import io.helixiam.authorization.service.mfa.TotpService;
import org.springframework.stereotype.Component;

/**
 * Whether a sign-in that otherwise completed must first enrol a second factor: the realm requires MFA and the user has
 * not enrolled TOTP. Shared by the post-password flow and the federated (broker) completion, so neither creates a full
 * session for such a user — the same rule as the magic-link and legacy password paths.
 */
@Component
public class MfaEnrolmentRequirement {

    private final MfaPolicyService policy;
    private final TotpService totp;

    public MfaEnrolmentRequirement(final MfaPolicyService policy, final TotpService totp) {
        this.policy = policy;
        this.totp = totp;
    }

    public boolean mustEnrol(final String realmId, final String userId) {
        return policy.required(realmId) && !totp.isEnrolled(userId);
    }
}
