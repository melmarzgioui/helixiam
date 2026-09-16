/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.domain.scope.admin;

/**
 * Helix IAM E8.5: which catalogue claim populates the OIDC {@code sub} (subject identifier) for a realm.
 * {@code claimKey} is a claim key from the realm's catalogue (e.g. {@code preferred_username}, {@code email});
 * the default is {@code sub} itself.
 */
public record SubjectClaimDto(String realmId, String claimKey) {
}
